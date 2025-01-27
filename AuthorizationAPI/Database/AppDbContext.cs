using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthorizationAPI.Database
{
    public class AppDbContext : IdentityDbContext<User>
    {
        public DbSet<Class> Classes { get; set; } 

        public AppDbContext(DbContextOptions<AppDbContext> options) : base (options)
        {
        }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<Class>()
                .HasMany(c => c.Students)
                .WithOne(u => u.Class);

            builder.HasDefaultSchema("auth");
        }
        
    }
}
