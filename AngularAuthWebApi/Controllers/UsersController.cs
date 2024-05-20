using AngularAuthWebApi.Helpers;
using AngularAuthWebApi.model;
using AngularAuthWebApi.Models;
using AngularAuthWebApi.Models.DTO;
using AngularAuthWebApi.UtilityServices;
using Dapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AngularAuthWebApi.Controllers
{
    public class UsersController : Controller
    {
        public readonly IConfiguration _config;
        private readonly Serilog.ILogger _log = Log.ForContext<Users>();
        private readonly IEmailService _emailService;
       public UsersController(IConfiguration configuration, IEmailService emailService) { 
            _config = configuration;
            _emailService = emailService;
       }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody]Users users)
        {
            string userName = users.username;

            try
            {
                using (var con = new SqlConnection(_config.GetConnectionString("SqlServerConnStr")))
                {
                    if (users == null)
                        return BadRequest();

                    string querry = @"SELECT [Id]
      ,[FirstName]
      ,[LastName]
      ,[UserName]
      ,[Email]
      ,[Password]
      ,[Role]
      ,[Token]
  FROM [AuthDbApi].[dbo].[UserDetails] where userName = @userName";
                    IEnumerable<Users> user = await con.QueryAsync<Users>(querry, new { userName });
                    if (!user.Any())
                        return BadRequest(new { message = "No User Found!" });
                        
                    if(!Passwordhash.VerifyPassword(users.password,user.First().password))
                        return BadRequest(new {message= "Password is Incorrect!"});

                    DateTime dateTime = DateTime.Now.AddDays(5);
                    querry = @"update UserDetails set Token = @userToken,RefreshToken = @refreshToken,TokenExpiryTime = @dateTime where UserName = @userName";

                    var userToken = CreateJWTToken(user.First());
                    var refreshToken = createRefreshToken().Result;

                    await con.QueryAsync(querry, new { userToken, refreshToken, dateTime,userName });

                    return user.Any() ? Ok(new RefreshTokenDTO { AccessToken= userToken,RefreshToken = refreshToken}): NotFound(new { message = "Not Found!" });
                }
            }
            catch(Exception ex)
            {
                Console.Write(ex.ToString());
                return BadRequest();
            }
        }

        [HttpPost("register")]

        public async Task<IActionResult> Register([FromBody]Users users)
        {
            try
            {
                using (var con = new SqlConnection(_config.GetConnectionString("SqlServerConnStr")))
                {
                    if (users == null)
                        return BadRequest("Not Found!");

                    if (await CheckUserNameExitAsync(users.username))
                        return BadRequest(new { message = "UserName Already Exits!" });

                    if (await CheckEmailExitAsync(users.email)) 
                        return BadRequest(new { message = "Email Already Exits!" });
                    
                    string valid = CheckPasswordStrength(users.password);
                    if (!string.IsNullOrEmpty(valid))
                        return BadRequest(new { message = valid });


                    users.password = Passwordhash.PasswordHash(users.password);
                    users.role = "User";
                    users.token = "";

                    string querry = @"Insert into Userdetails (FirstName,LastName,UserName,Password,Role,Token,Email) 
values(@FirstName,@LastName,@UserName,@Password,@Role,@Token,@Email)";

                    await con.ExecuteAsync(querry, users);
                    return Ok(new {message= "registered!"});
                }
            }
            catch(Exception ex)
            {
                Console.Write(ex);
                return BadRequest();
            }
        }

       [Authorize(Roles = "Admin")]
        [HttpGet("UserDetails")]
        public async Task<IEnumerable<Users>> GetUsers()
        {
            try { 
                using(var con = new SqlConnection(_config.GetConnectionString("SqlServerConnStr")))
                {
                    return await con.QueryAsync<Users>(@"Select * from UserDetails");
                }
                
            }catch(Exception ex)
            {
                _log.Error(ex, "GetUsers()");
            }

            return null;
        }

        [HttpPost("refreshToken")]
        public async Task<IActionResult> RefeshToken([FromBody]RefreshTokenDTO refreshTokenDTO)
        {
            if (refreshTokenDTO is null)
                return BadRequest("Invalid Request!");
            string? AccessToken = refreshTokenDTO.AccessToken;
            string? RefreshToken = refreshTokenDTO.RefreshToken;
            var principal = GetClaimsPrincipal(AccessToken);
            var userName = principal.Identity?.Name;
            try
            {
                using(var con = new SqlConnection(_config.GetConnectionString("SqlServerConnStr")))
                {
                    string querry = @"SELECT [Id]
      ,[FirstName]
      ,[LastName]
      ,[UserName]
      ,[Email]
      ,[Password]
      ,[Role]
      ,[TokenExpiryTime]
      ,[RefreshToken]
      ,[Token]
  FROM [AuthDbApi].[dbo].[UserDetails] where UserName = @userName";
                    Users user = (await con.QueryAsync<Users>(querry, new { userName })).First();
                    if (user is null || user.RefreshToken != RefreshToken || user.TokenExpiryTime <= DateTime.Now)
                        return BadRequest("Invalid Token!");
                    
                    string username = user.username;
                    string newAccessToken = CreateJWTToken(user);
                    string newRefreshToken = createRefreshToken().Result;

                    querry = @"Update UserDetails Set RefreshToken = @newRefreshToken where UserName = @username";
                    await con.QueryAsync(querry, new { newRefreshToken, username });
                    return Ok(new RefreshTokenDTO { AccessToken = newAccessToken, RefreshToken = newRefreshToken});
                }
            }catch(Exception ex)
            {
                _log.Error(ex, "RefeshToken()");
            }
            return NotFound();
        }

        [HttpPost("sent-reset-email/{email}")]
        public async Task<IActionResult> ResetEmail(string email)
        {
            try {
                using (var con = new SqlConnection(_config.GetConnectionString("SqlServerConnStr")))
                {
                    string querry = @"SELECT [Id]
      ,[FirstName]
      ,[LastName]
      ,[UserName]
      ,[Email]
      ,[Password]
      ,[Role]
      ,[TokenExpiryTime]
      ,[RefreshToken]
      ,[Token]
      ,[ResetPasswordToken]
      ,[ResetPasswordExpiry]
  FROM [AuthDbApi].[dbo].[UserDetails] where Email= @email";
                    IEnumerable<Users> user = await con.QueryAsync<Users>(querry, new { email });
                    if (!user.Any())
                        return BadRequest(new { message = "Email Not Found!" });

                    var tokenBytes = RandomNumberGenerator.GetBytes(64);
                    var resetPasswordToken = Convert.ToBase64String(tokenBytes);
                    var resetPasswordExpiry = DateTime.Now.AddMinutes(15);

                    querry = @"Update UserDetails Set ResetPasswordToken = @resetPasswordToken,
ResetPasswordExpiry = @resetPasswordExpiry Where Email = @email ";

                    Email emailMessage = new Email(email, "Rest Password!", EmailStringBody.EmailBody(email, resetPasswordToken));
                    _emailService.SendEmail(emailMessage);

                    await con.ExecuteScalarAsync<Users>(querry, new { email, resetPasswordToken, resetPasswordExpiry });
                    return Ok(new { StatusCode = 200, Message = "Sent Successful!" });

                }
            
            }catch(Exception ex)
            {
                _log.Error(ex, "ResetPassword()");
            }
            return BadRequest();
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody]ResetEmailDTO resetEmailDTO)
        {
            var resetEmailToken = resetEmailDTO.EmailToken.Replace(" ", "+");
            var email = resetEmailDTO.Email;
            try
            {
                using(var con = new SqlConnection(_config.GetConnectionString("SqlServerConnStr")))
                {
                    string querry = @"SELECT [Id]
      ,[FirstName]
      ,[LastName]
      ,[UserName]
      ,[Email]
      ,[Password]
      ,[Role]
      ,[TokenExpiryTime]
      ,[RefreshToken]
      ,[Token]
      ,[ResetPasswordToken]
      ,[ResetPasswordExpiry]
  FROM [AuthDbApi].[dbo].[UserDetails] where Email = @email";
                    IEnumerable<Users> user = await con.QueryAsync<Users>(querry, new { email });
                    if (!user.Any())
                        return BadRequest(new {StatusCode = 400, message = "Email Not Found!" });
                    if (user.First().ResetPasswordToken != resetEmailDTO.EmailToken || user.First().ResetPasswordExpiry <= DateTime.Now)
                        return NotFound(new { StatusCode = 400, Message = "Invalid Reset Link!" });
                    var newPassword = Passwordhash.PasswordHash(resetEmailDTO.NewPassword);
                    await con.ExecuteScalarAsync<Users>(@"Update UserDetails Set Password = @newPassword Where Email = @email", new { newPassword, email });
                    
                    return Ok(new { StatusCode = 200, Message = "Successfull!" });
                }
            }catch(Exception ex)
            {
                _log.Error(ex, "ResetEmail()");
            }
            return BadRequest();
        }
        private async Task<bool> CheckUserNameExitAsync(string username)
        {
            try
            {
                using(var con = new SqlConnection(_config.GetConnectionString("SqlServerConnStr")))
                {
                    string querry = @"select UserName from UserDetails";
                    var users = await con.QueryAsync<string>(querry);
                    if(users.Where(u => u.ToString() == username).Any())
                        return true;
                    return false;
                }
            }catch(Exception ex)
            {
                Console.Write(ex.ToString());
                return false;
            }
        }

        private async Task<bool> CheckEmailExitAsync(string email)
        {
            try
            {
                using (var con = new SqlConnection(_config.GetConnectionString("SqlServerConnStr")))
                {
                    string querry = @"select Email from UserDetails";
                    var users = await con.QueryAsync<string>(querry);
                    if (users.Where(u => u.ToString() == email).Any())
                        return true;
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.Write(ex.ToString());
                return false;
            }
        }

        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();

            if (password.Length < 8)
                sb.Append("Password must be contain atleast 8 charcters!"+ Environment.NewLine);

            if (!(Regex.IsMatch(password, "[a-z]")) || !(Regex.IsMatch(password, "[A-Z]")) || !(Regex.IsMatch(password, "[0-9]")))
                sb.Append("Password should be AlpaNumeric!" + Environment.NewLine);

            if (!Regex.IsMatch(password, @"[!@#$%^&*()_+=\[{\]};:<>|./?,-]"))
                sb.Append("password Must contain Specail Characters!" + Environment.NewLine);

            return sb.ToString();
        }

        private string CreateJWTToken(Users users)
        {
            try
            {
                var JwtTokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes("This is Very SecertKey!@#$%");
                var identity = new ClaimsIdentity(new Claim[]
                {
                new Claim(ClaimTypes.Role,users.role),
                new Claim(ClaimTypes.Name, $"{users.username}")
                });

                var cradentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = identity,
                    Expires = DateTime.Now.AddSeconds(10),
                    SigningCredentials = cradentials
                };

                var token = JwtTokenHandler.CreateToken(tokenDescriptor);
                return JwtTokenHandler.WriteToken(token);
            }catch(Exception ex)
            {
                Console.Write(ex);
                return "Invalid Token!";
            }
        }

        private async Task<string> createRefreshToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(tokenBytes);

            try
            {
                using(var con = new SqlConnection(_config.GetConnectionString("SqlServerConnStr")))
                {
                    string querry = @"SELECT [Id]
      ,[FirstName]
      ,[LastName]
      ,[UserName]
      ,[Email]
      ,[Password]
      ,[Role]
      ,[Token]
      ,[RefreshToken]
      ,[TokenExpiryTime]
  FROM [AuthDbApi].[dbo].[UserDetails] where RefreshToken=@refreshToken";
                    IEnumerable<Users> tokenINUser = await con.QueryAsync<Users>(querry, new { refreshToken });
                    if (tokenINUser.Any())
                    {
                       return await createRefreshToken();
                    }
                    return refreshToken;
                }
            }catch(Exception ex)
            {
                _log.Error(ex, "createRefreshToken()");
            }

            return null;
        }

        private ClaimsPrincipal GetClaimsPrincipal(string token)
        {
            var key = Encoding.ASCII.GetBytes("This is Very SecertKey!@#$%");
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false
            };
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = jwtTokenHandler.ValidateToken(token,tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (securityToken is null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha512, StringComparison.InvariantCulture))
                throw new SecurityTokenException("Invlaid Token!");
            return principal;
        }
        
    }

}
