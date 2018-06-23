using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using LogReg.Models;

namespace LogReg.Controllers
{
    public class UserController : Controller
    {
        private readonly DbConnector _dbConnector;
        public UserController(DbConnector connect)
        {
            _dbConnector = connect;
        }
        // GET: /
        [HttpGet("")]
        public IActionResult Main()
        {
            // Check if userID in session, if true, redirect to dashboard
            int? userID = HttpContext.Session.GetInt32("userID");
            if(userID != null)
            {
                return RedirectToAction("Index");
            }
            return View();
        }
        // GET: /dashboard 
        [HttpGet("index")]
        public IActionResult Index()
        {
            // Check if userID is not in session, if true, redirect to home 
            int? userID = HttpContext.Session.GetInt32("userID");
            if(userID == null)
            {
                return RedirectToAction("Main");
            }
            return View();
        }
        // GET: /register 
        [HttpGet("register")]
        public IActionResult Register() 
        {
            ViewBag.error = ModelState.Values;
            // Check if userID in session, if true, redirect to dashboard
            int? userID = HttpContext.Session.GetInt32("userID");
            if(userID != null)
            {
                return RedirectToAction("Index");
            }
            return View();
        }
        // POST: /register
        [HttpPost("register")]
        public IActionResult Register(UserReg user)
        {
            if(ModelState.IsValid)
            {
                // Check for unique email 
                var users = _dbConnector.Query($"SELECT * FROM user WHERE email = '{user.Email}';");
                if(users.Count > 0)
                {
                    ViewBag.errors = ModelState.Values;
                    ModelState.AddModelError("Email", "Email already exists");
                    return View(user);
                }
                else
                {   
                    // Hash password and add user to database, store user id in session 
                    PasswordHasher<UserReg> hasher = new PasswordHasher<UserReg>();
                    string hashed = hasher.HashPassword(user, user.Password);
                    string query = $"INSERT INTO user (first_name, last_name, email, password, created_at, updated_at) VALUES('{user.FirstName}', '{user.LastName}', '{user.Email}', '{hashed}', NOW(), NOW());";
                    _dbConnector.Execute(query);
                    int? userID = (int)_dbConnector.Query("SELECT id FROM user ORDER BY created_at DESC LIMIT 1;")[0]["id"];
                    HttpContext.Session.SetInt32("userID", (int)userID);
                    return RedirectToAction("Index");
                }
            }
            return View(user);
        }
        // GET: /login 
        [HttpGet("login")]
        public IActionResult Login()
        {
            ViewBag.error = ModelState.Values;
            // Check if userID in session, if true, redirect to dashboard
            int? userID = HttpContext.Session.GetInt32("userID");
            if(userID != null)
            {
                return RedirectToAction("Index");
            }
            return View();
        }
        // POST: /login 
        [HttpPost("login")]
        public IActionResult Login(UserLog user)
        {
            if(ModelState.IsValid)
            {
                ViewBag.errors = ModelState.Values;
                // Check if a user is returned based on email, return error if false
                var users = _dbConnector.Query($"SELECT id, password FROM user WHERE email = '{user.LoginEmail}';");
                if(users.Count == 0)
                {
                    
                    ModelState.AddModelError("LoginEmail", "Incorrect email/password");
                    return View(user);
                }
                else 
                {
                    // Verify password, if failed return error, if succeed redirec to dashboard and store user id in session 
                    PasswordHasher<UserLog> hasher = new PasswordHasher<UserLog>();
                    string hashedPass = (string)users[0]["password"];
                    PasswordVerificationResult result = hasher.VerifyHashedPassword(user, hashedPass, user.LoginPassword);
                    if(result == PasswordVerificationResult.Failed)
                    {
                        ModelState.AddModelError("LoginPassword", "Incorrect email/password");
                        return View(user);
                    }
                    else
                    {
                        int? userID = (int)users[0]["id"];
                        HttpContext.Session.SetInt32("userID", (int)userID);
                        return RedirectToAction("Index");
                    }
                }
            }
            return View(user);
        }
        // GET: /logout , clear session, redirect to home 
        [HttpGet("logout")]
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Index");
        }
    }
}