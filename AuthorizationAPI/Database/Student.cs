using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace AuthorizationAPI.Database
{
    public class Student : User
    {
        public string? Name { get; set; }


    }
}
