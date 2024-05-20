using Microsoft.EntityFrameworkCore;
using AngularAuthWebApi.model;

namespace AngularAuthWebApi.Context
{
    public class userDBContext: DbContext
    {
        public userDBContext(DbContextOptions<userDBContext> options): base(options) { }

        public DbSet<Users> Users { get; set; }

        protected void onModelCreating(ModelBuilder modelbuilder)
        {
            modelbuilder.Entity<Users>().ToTable("SqlServerConnStr");
        }

    }
}
