using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Web;

namespace NewCldAdmin.Models
{
    public class registration
    {
        [Key]
        public long xid { get; set; }

        public string AccrediationType { get; set; }

        public string Sys_ID { get; set; }

        public string Firstname { get; set; }

        public string Surname { get; set; }

        public string Email { get; set; }

        public string xpassword { get; set; }

        public string DateOfBrith { get; set; }

        public string IncorporatedDate { get; set; }

        public string Nationality { get; set; }

        public string PhoneNumber { get; set; }

        public string CompanyName { get; set; }

        [Column(TypeName = "text")]
        public string CompanyAddress { get; set; }

        public string ContactPerson { get; set; }

        public string ContactPersonPhone { get; set; }

        public string CompanyWebsite { get; set; }

        [Column(TypeName = "text")]
        public string Certificate { get; set; }

        [Column(TypeName = "text")]
        public string Introduction { get; set; }

        [Column(TypeName = "text")]
        public string Principal { get; set; }

        public string xreg_date { get; set; }

        public string xstatus { get; set; }

        public string xvisible { get; set; }

        public string xsync { get; set; }
        [NotMapped]
        public JObject Token { get; set; }

       

        [Column(TypeName = "text")]
        public string logo { get; set; }
    }
}