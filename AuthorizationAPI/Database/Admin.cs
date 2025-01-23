using Microsoft.AspNetCore.Identity;

namespace AuthorizationAPI.Database
{
    public class Admin : User
    {
        public string? Name { get; set; }

    }
}
