using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Web;

namespace NewCldAdmin.Models
{
    public class TopMenu
    {
        [DatabaseGeneratedAttribute(DatabaseGeneratedOption.Identity)]
        public int ID { get; set; }
        [MaxLength(200)]
        [Required]
        //[Key, Column(Order = 1)]
        [Key]
        public String Menu_Code { get; set; }

        public String Menu_Name { get; set; }

        public String SelectMenu { get; set; }
        public String CreateMenu { get; set; }

        public String UpdateMenu { get; set; }

        public String DeleteMenu { get; set; }

        public String RoleName { get; set; }

        public virtual ICollection<RolesPriviledges> RolesPriviledges { get; set; }
    }
}