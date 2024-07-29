using AuthService.Models;

namespace AuthService.Interfaces
{
    public interface IUserRepository
    {
        void AddUser(User user);
        User GetUserByUsername(string username);
        bool ValidateUserCredentials(string username, string password);
    }

}
