using AngularAuthAPI.Context;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.RegularExpressions;
using System;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System.Security.Cryptography;
using AngularAuthAPI.Models.Dto;
using System.Data;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _appDbContext;

        public  UserController(AppDbContext appDbContext) {
            _appDbContext = appDbContext;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authonticate([FromBody] User userObj)
        {
            if(userObj == null)
            {
                return BadRequest();
            }

            var user =await _appDbContext.Users
                .FirstOrDefaultAsync(x=>x.Username== userObj.Username  );
            if (user == null)
                return NotFound(new { Message = "User Not Found" });

            if (!PasswordHasher.VerifyPassword(userObj.Password, user.Password)){
                return NotFound(new { Message = "Password is incorrect" });
            }

            user.Token = CreateJwt(user);
            var newAccessToken = user.Token;
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(1);
            await _appDbContext.SaveChangesAsync(); 

            return Ok(new TokenApiDto()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            }); ;


        }

        [HttpPost("register")]
        public async Task <IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null) 
                return BadRequest();

            //Check Username
            if(await CheckUserNameExistAsync(userObj.Username))
                return BadRequest(new { Message="Username Already Exist!" });

            //Check Email
            if (await CheckEmailExistAsync(userObj.Email))
                return BadRequest(new { Message = "Email Already Exist!" });

            //Check password Strength
            var pass = checkPasswordStrength(userObj.Password);
            if(!string.IsNullOrEmpty(pass))
                return BadRequest(new { Message = pass });

            userObj.Password=PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token= "";
            await _appDbContext.Users.AddAsync(userObj);
            await _appDbContext.SaveChangesAsync();
            return Ok(new { Message = "Login Successfull" });
        }



        private   Task<bool> CheckUserNameExistAsync(string userName)
        => _appDbContext.Users.AnyAsync(x => x.Username == userName);

        private Task<bool> CheckEmailExistAsync(string Email)
         => _appDbContext.Users.AnyAsync(x => x.Email == Email);


        private string checkPasswordStrength(string password)
        {

            StringBuilder sb = new StringBuilder();
            if (password.Length < 8) 
                sb.Append("Mininum password length shoul be 8 " + Environment.NewLine);
            if ((Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]")
                && Regex.IsMatch(password,"[0-9]")))
                sb.Append("Password should be Alphanumeric"+Environment.NewLine);
            if (!Regex.IsMatch(password, "[<,>,@,!,#,$,%,^,&,*,(,),_,-,=,+]"))
                sb.Append("Password Should be containing Special Chars" + Environment.NewLine);
            return sb.ToString();
        }


        private string CreateJwt(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("Nasar@123Intel@2023");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new  Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name,$"{user.Username} "),
                new Claim("Id", user.Id.ToString())

            });

            //var claims = new[] {
            //           new  Claim(ClaimTypes.Role, user.Role),
            //           new Claim(ClaimTypes.Name,$"{user.FirstName}{user.LastName}"),
            //            new Claim("Id", user.Id.ToString())
            //        };

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
            var tokenDescription = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddSeconds(2),
                SigningCredentials = credentials,
            };

            var token = jwtTokenHandler.CreateToken(tokenDescription);

            return jwtTokenHandler.WriteToken(token);
        }

        private string CreateRefreshToken()
        {
            var tokeBytes=RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(tokeBytes);
            var tokeInUser=_appDbContext.Users.Any(a=>a.RefreshToken== refreshToken);
            if(tokeInUser)
            {
                return CreateRefreshToken();
            }
            return refreshToken;
        }

        private ClaimsPrincipal GetPrincipleFromExpiredToken(string token)
        {
            var tokenvalidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("Nasar@123Intel@2023")),
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal =tokenHandler.ValidateToken(token,tokenvalidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if(jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,StringComparison.InvariantCultureIgnoreCase)) 
              throw new SecurityTokenException("This is Invalid Token ");
             
            return principal;
        }

        [Authorize]
        [HttpGet]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok (await _appDbContext.Users.ToListAsync()); 
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh (TokenApiDto tokenApiDto)
        {
            if (tokenApiDto is null  )
                return BadRequest("Invalid Clinent Request");
            string accessToken =tokenApiDto.AccessToken; 
            string refreshToken=tokenApiDto.RefreshToken;
            var principal =GetPrincipleFromExpiredToken(accessToken);
            var username = principal.Identity.Name; 
            var user = await _appDbContext.Users.FirstOrDefaultAsync(u =>u.Username== username);
            if(user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime<=DateTime.Now)
                return BadRequest("Invalid   Request");

            var newAccessToken = CreateJwt(user);
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            await _appDbContext.SaveChangesAsync();
            return Ok(new TokenApiDto()
            {
                AccessToken= newAccessToken,
                RefreshToken=newRefreshToken,
            });
            

        }

    }
}
