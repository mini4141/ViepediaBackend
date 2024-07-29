using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthService.Interfaces;
using AuthService.Models;
using Microsoft.IdentityModel.Tokens;
using Moq;
using NUnit.Framework;

namespace AuthServiceTests
{
    public class AuthServiceTests
    {
        private Mock<IUserRepository> _userRepositoryMock;
        private AuthService.Services.AuthService _authService;

        [SetUp]
        public void Setup()
        {
            _userRepositoryMock = new Mock<IUserRepository>();
            _authService = new AuthService.Services.AuthService(_userRepositoryMock.Object);
        }

        [Test]
        public void Register_NewUser_AddsUserToRepository()
        {
            // Arrange
            var username = "testuser";
            var password = "password123";

            // Act
            _authService.Register(username, password);

            // Assert
            _userRepositoryMock.Verify(repo => repo.AddUser(It.Is<User>(u => u.Username == username && VerifyPassword(password, u.PasswordHash))), Times.Once);
        }

        private bool VerifyPassword(string plainPassword, string hashedPassword)
        {
            return BCrypt.Net.BCrypt.Verify(plainPassword, hashedPassword);
        }

        [Test]
        public void Login_ValidCredentials_ReturnsToken()
        {
            // Arrange
            var username = "testuser";
            var password = "password123";
            var passwordHash = BCrypt.Net.BCrypt.HashPassword(password);

            _userRepositoryMock.Setup(repo => repo.ValidateUserCredentials(username, password)).Returns(true);
            _userRepositoryMock.Setup(repo => repo.GetUserByUsername(username)).Returns(new User { Username = username, PasswordHash = passwordHash });

            // Act
            var token = _authService.Login(username, password);

            // Assert
            Assert.That(token, Is.Not.Null);
        }

        [Test]
        public void Login_InvalidCredentials_ThrowsUnauthorizedAccessException()
        {
            // Arrange
            var username = "testuser";
            var password = "wrongpassword";

            _userRepositoryMock.Setup(repo => repo.ValidateUserCredentials(username, password)).Returns(false);

            // Act & Assert
            Assert.That(() => _authService.Login(username, password), Throws.TypeOf<UnauthorizedAccessException>());
        }

        [Test]
        public void ValidateToken_ValidToken_ReturnsClaimsPrincipal()
        {
            // Arrange
            var username = "testuser";
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("your_secret_key_hereyour_secret_key_hereyour_secret_key_here");
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, username) }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            // Act
            var principal = _authService.ValidateToken(tokenString);

            // Assert
            Assert.That(principal, Is.Not.Null);
            Assert.That(principal.Identity.Name, Is.EqualTo(username));
        }

        [Test]
        public void ValidateToken_InvalidToken_ThrowsSecurityTokenException()
        {
            // Arrange
            var invalidToken = "invalid_token";

            // Act & Assert
            Assert.That(() => _authService.ValidateToken(invalidToken), Throws.TypeOf<SecurityTokenMalformedException>());
        }
    }
}
