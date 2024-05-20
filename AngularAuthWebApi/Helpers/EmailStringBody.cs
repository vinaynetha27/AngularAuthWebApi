namespace AngularAuthWebApi.Helpers
{
    public static class EmailStringBody
    {
        public static string EmailBody(string email, string emailToken)
        {
            return $@"
                    <html>
    <head></head>
    <body style=""margin: 0px;padding: 0px;font-family: Arial, Helvetica, sans-serif;"">
        <div style=""height: auto;background: linear-gradient(to top,#c7bebe 50%,#929292 90%) no-repeat; width: 400px;padding: 30px;"">
            <div>
                <h1>Reset Password</h1>
                <hr>
                <p>Please tap below button to reset Pasword.</p>
                <a href=""http://localhost:4201/reset?email={email}&code={emailToken}"" target=""_blank"" style=""background: #0a0707;padding: 10px;border: none;
                color: white;border-radius: 45px;display: block;margin: 0 auto; width: 50%;text-align: center;text-decoration: none;"">Reset</a>
                <p>Kind regards! <br>
                Let Code.</p>
            </div>
        </div>
    </body>
</html>";
        }
    }
}
