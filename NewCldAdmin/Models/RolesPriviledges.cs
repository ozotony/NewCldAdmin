using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Web;

namespace NewCldAdmin.Models
{
    public class RolesPriviledges
    {
        [DatabaseGeneratedAttribute(DatabaseGeneratedOption.Identity)]
        [Key]
        public int MenuID { get; set; }

        public string View { get; set; }

        public string CreateNew { get; set; }

        public string UpadateNew { get; set; }

        public string DeleteNew { get; set; }

        public String RoleName { get; set; }

        [ForeignKey("TopMenu")]
        public String Menu_Code { get; set; }

        public virtual TopMenu TopMenu { get; set; }
    }
}