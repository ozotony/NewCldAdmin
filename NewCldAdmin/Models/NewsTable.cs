using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Web;

namespace NewCldAdmin.Models
{
    public class NewsTable
    {
        [DatabaseGeneratedAttribute(DatabaseGeneratedOption.Identity)]
        [Key]
        public int NewsID { get; set; }
       
      
        [Required]
        public String NewsContent { get; set; }


        [Required]
        public String Headline { get; set; }

        [Required]
        public DateTime Date_Added { get; set; }

        
        public String  Status { get; set; }

        public String Archive { get; set; }

        [Required]
        public String  Userid { get; set; }

       
        public String ApprovedBy { get; set; }
    }
}