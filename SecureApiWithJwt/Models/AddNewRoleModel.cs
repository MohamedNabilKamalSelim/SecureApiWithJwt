using System.ComponentModel.DataAnnotations;

namespace SecureApiWithJwt.Models
{
    public class AddNewRoleModel
    {
        [Required]
        public string RoleName { get; set; }
    }
}
