﻿namespace AngularAuthWebApi.Models.DTO
{
    public class RefreshTokenDTO
    {
        public string? AccessToken {  get; set; }
        public string? RefreshToken { get; set;}
    }
}
