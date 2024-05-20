using AngularAuthWebApi.Models;
using MailKit.Net.Smtp;
using MimeKit;
using Serilog;

namespace AngularAuthWebApi.UtilityServices
{
    public class EmailService: IEmailService
    {
        public IConfiguration _config;
        public Serilog.ILogger _log = Log.ForContext<Email>() ;
        public EmailService(IConfiguration configuration) { 
            _config = configuration;
        }

        public void SendEmail(Email email)
        {
            try {
                var emailMessage = new MimeMessage();
                var from = _config["EmailSettings:From"];
                emailMessage.From.Add(new MailboxAddress("Let Code", from));
                emailMessage.To.Add(new MailboxAddress(email.To, email.To));
                emailMessage.Subject = email.Subject;
                emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Html) {
                    Text = string.Format(email.Content)
                };

                using (var client = new SmtpClient())
                {
                    try
                    {
                        client.Connect(_config["EmailSettings:SmtpServer"], 465, true);
                        client.Authenticate(_config["EmailSettings:From"], _config["EmailSettings:Password"]);
                        client.Send(emailMessage);
                    }
                    finally
                    {
                        client.Disconnect(true);
                        client.Dispose();
                    }
                }
            }catch(Exception ex)
            {
                _log.Error(ex, "SendEmail()");
            }
        }
    }
}
