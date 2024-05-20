namespace AngularAuthWebApi.Models
{
    public class Email
    {
        public string To { get; set; }
        public string Subject { get; set; }
        public string Content { get; set; }
        public Email(string to, string subject, string content) { 
            To= to;
            Content= content;
            Subject= subject;
        }
    }
}
