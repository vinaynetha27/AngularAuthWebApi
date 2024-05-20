using System.ComponentModel.DataAnnotations;

namespace AngularAuthWebApi.model
{
    public class Users
    {
       
       

        public string firstName { get; set; }

        public string lastName { get; set; }

        public string username { get; set; }

        public string email { get; set; }

        public string password { get; set; }

        public string role { get; set; }

        public string token { get; set; }

        public string RefreshToken { get;set; }

        public DateTime TokenExpiryTime { get; set; }

        public string ResetPasswordToken { get; set; }
        public DateTime ResetPasswordExpiry { get; set;    }

    }
}
