using AngularAuthWebApi.Models;

namespace AngularAuthWebApi.UtilityServices
{
    public interface IEmailService
    {
        public void SendEmail(Email email);
    }
}
