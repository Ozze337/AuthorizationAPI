using AuthorizationAPI.Database;

public class Class
{
    public int Id { get; set; }
    public string? Name { get; set; }
    public string? Description { get; set; }

    public User Teacher { get; set; }

    public ICollection<User> Students { get; }
}
