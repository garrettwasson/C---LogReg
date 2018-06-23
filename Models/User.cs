using System;
using System.ComponentModel.DataAnnotations;

namespace LogReg.Models
{
    public abstract class BaseEntity {}
    
    public class UserReg : BaseEntity
    {
        //-------ID
        public int ID {get; set;}

        //-------First Name 
        [Required(ErrorMessage = "First name is required!")]
        [MinLength(2, ErrorMessage = "First name must have at least two characters!")]
        [RegularExpression("^[a-zA-z]*$", ErrorMessage = "First name can only contain letters!")]
        public string FirstName {get; set;}

        //-------Last Name 
        [Required(ErrorMessage = "Last name is required!")]
        [MinLength(2, ErrorMessage = "Last name must have at least two characters!")]
        [RegularExpression("^[a-zA-z]*$", ErrorMessage = "Last name can only contain letters!")]
        public string LastName {get; set;}

        //-------Email 
        [Required(ErrorMessage = "Email is required!")]
        [EmailAddress(ErrorMessage = "Entered email was invalid!")]
        public string Email {get; set;}

        //-------Password 
        [Required(ErrorMessage = "Password is required!")]
        [MinLength(8, ErrorMessage = "Password must be at least eight characters in length!")]
        [DataType(DataType.Password)]
        public string Password {get; set;}

        //-------Confirm Password 
        [Compare("Password", ErrorMessage = "Passwords do not match! Please, try again!")]
        [DataType(DataType.Password)]
        public string ConfirmPassword {get; set;}
    }
    public class UserLog : BaseEntity 
    {
         //-------Email 
        [Required(ErrorMessage = "Email is required!")]
        [EmailAddress(ErrorMessage = "Entered email was invalid!")]
        public string LoginEmail {get; set;}

        //-------Password 
        [Required(ErrorMessage = "Password is required!")]
        [DataType(DataType.Password)]
        public string LoginPassword {get; set;}
    }
}