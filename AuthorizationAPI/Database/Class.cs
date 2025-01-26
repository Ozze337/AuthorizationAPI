using AuthorizationAPI.Database;

public class Class
{
    public int Id { get; set; }
    public string? Name { get; set; }
    public string? Description { get; set; }
    public string? TeacherId { get; set; }
    public Teacher? Teacher { get; set; }
}
