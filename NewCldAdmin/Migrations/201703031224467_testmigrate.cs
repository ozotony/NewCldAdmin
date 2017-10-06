namespace NewCldAdmin.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class testmigrate : DbMigration
    {
        public override void Up()
        {
            CreateTable(
                "dbo.RolesPriviledges",
                c => new
                    {
                        MenuID = c.Int(nullable: false, identity: true),
                        View = c.String(),
                        CreateNew = c.String(),
                        UpadateNew = c.String(),
                        DeleteNew = c.String(),
                        RoleName = c.String(),
                        Menu_Code = c.String(maxLength: 200),
                    })
                .PrimaryKey(t => t.MenuID)
                .ForeignKey("dbo.TopMenus", t => t.Menu_Code)
                .Index(t => t.Menu_Code);
            
            CreateTable(
                "dbo.TopMenus",
                c => new
                    {
                        Menu_Code = c.String(nullable: false, maxLength: 200),
                        ID = c.Int(nullable: false, identity: true),
                        Menu_Name = c.String(),
                        SelectMenu = c.String(),
                        CreateMenu = c.String(),
                        UpdateMenu = c.String(),
                        DeleteMenu = c.String(),
                        RoleName = c.String(),
                    })
                .PrimaryKey(t => t.Menu_Code);
            
        }
        
        public override void Down()
        {
            DropForeignKey("dbo.RolesPriviledges", "Menu_Code", "dbo.TopMenus");
            DropIndex("dbo.RolesPriviledges", new[] { "Menu_Code" });
            DropTable("dbo.TopMenus");
            DropTable("dbo.RolesPriviledges");
        }
    }
}
