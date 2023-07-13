using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using System.ComponentModel.DataAnnotations;

namespace LoginWithCookieAuth.Pages
{
    public class IndexModel : PageModel
    {
        [BindProperty]
        public LoginInput UserInput { get; set; }

        public bool IsLoggedIn { get; set; }

        public void OnGet()
        {
            IsLoggedIn = User.Identity.IsAuthenticated;
        }

        public async Task<IActionResult> OnPost()
        {
            if (ModelState.IsValid)
            {
                if (UserInput.Username == "intern" && UserInput.Password == "summer 2023 july")
                {
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, UserInput.Username),
                        new Claim(ClaimTypes.Role, "User")
                    };

                    var claimsIdentity = new ClaimsIdentity(
                        claims,
                        CookieAuthenticationDefaults.AuthenticationScheme
                    );

                    await HttpContext.SignInAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme,
                        new ClaimsPrincipal(claimsIdentity)
                    );

                    return RedirectToPage();
                }
                else
                {
                    ModelState.AddModelError("Invalid", "Invalid login credentials.");
                }
            }

            return Page();
        }

        public async Task<IActionResult> OnPostHandleLogout()
        {
            await HttpContext.SignOutAsync(
                CookieAuthenticationDefaults.AuthenticationScheme
            );

            return RedirectToPage();
        }
    }

    public class LoginInput
    {
        [Required(ErrorMessage = "Username is required.")]
        public string Username { get; set; }

        [Required(ErrorMessage = "Password is required.")]
        public string Password { get; set; }
    }
}
