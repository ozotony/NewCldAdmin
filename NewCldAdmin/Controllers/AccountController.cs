using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.ModelBinding;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using NewCldAdmin.Models;
using NewCldAdmin.Providers;
using NewCldAdmin.Results;
using System.Linq;
using Newtonsoft.Json.Linq;
using System.Threading;

namespace NewCldAdmin.Controllers
{
    [Authorize]
    [RoutePrefix("api/Account")]
    public class AccountController : ApiController
    {
        private const string LocalLoginProvider = "Local";
        private ApplicationUserManager _userManager;

        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager,
            ISecureDataFormat<AuthenticationTicket> accessTokenFormat)
        {
            UserManager = userManager;
            AccessTokenFormat = accessTokenFormat;
        }

        private ApplicationRoleManager _AppRoleManager = null;

        protected ApplicationRoleManager AppRoleManager
        {
            get
            {
                return _AppRoleManager ?? Request.GetOwinContext().GetUserManager<ApplicationRoleManager>();
            }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? Request.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; private set; }

        // GET api/Account/UserInfo
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("UserInfo")]
        public UserInfoViewModel GetUserInfo()
        {
            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            return new UserInfoViewModel
            {
                Email = User.Identity.GetUserName(),
                HasRegistered = externalLogin == null,
                LoginProvider = externalLogin != null ? externalLogin.LoginProvider : null
            };
        }

        // POST api/Account/Logout
        [Route("Logout")]
        public IHttpActionResult Logout()
        {
            Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            return Ok();
        }

        // GET api/Account/ManageInfo?returnUrl=%2F&generateState=true
        [Route("ManageInfo")]
        public async Task<ManageInfoViewModel> GetManageInfo(string returnUrl, bool generateState = false)
        {
            IdentityUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

            if (user == null)
            {
                return null;
            }

            List<UserLoginInfoViewModel> logins = new List<UserLoginInfoViewModel>();

            foreach (IdentityUserLogin linkedAccount in user.Logins)
            {
                logins.Add(new UserLoginInfoViewModel
                {
                    LoginProvider = linkedAccount.LoginProvider,
                    ProviderKey = linkedAccount.ProviderKey
                });
            }

            if (user.PasswordHash != null)
            {
                logins.Add(new UserLoginInfoViewModel
                {
                    LoginProvider = LocalLoginProvider,
                    ProviderKey = user.UserName,
                });
            }

            return new ManageInfoViewModel
            {
                LocalLoginProvider = LocalLoginProvider,
                Email = user.UserName,
                Logins = logins,
                ExternalLoginProviders = GetExternalLogins(returnUrl, generateState)
            };
        }

        // POST api/Account/ChangePassword
        [Route("ChangePassword")]
        public async Task<IHttpActionResult> ChangePassword(ChangePasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword,
                model.NewPassword);
            
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/SetPassword
        [Route("SetPassword")]
        public async Task<IHttpActionResult> SetPassword(SetPasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/AddExternalLogin
        [Route("AddExternalLogin")]
        public async Task<IHttpActionResult> AddExternalLogin(AddExternalLoginBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);

            AuthenticationTicket ticket = AccessTokenFormat.Unprotect(model.ExternalAccessToken);

            if (ticket == null || ticket.Identity == null || (ticket.Properties != null
                && ticket.Properties.ExpiresUtc.HasValue
                && ticket.Properties.ExpiresUtc.Value < DateTimeOffset.UtcNow))
            {
                return BadRequest("External login failure.");
            }

            ExternalLoginData externalData = ExternalLoginData.FromIdentity(ticket.Identity);

            if (externalData == null)
            {
                return BadRequest("The external login is already associated with an account.");
            }

            IdentityResult result = await UserManager.AddLoginAsync(User.Identity.GetUserId(),
                new UserLoginInfo(externalData.LoginProvider, externalData.ProviderKey));

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/RemoveLogin
        [Route("RemoveLogin")]
        public async Task<IHttpActionResult> RemoveLogin(RemoveLoginBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result;

            if (model.LoginProvider == LocalLoginProvider)
            {
                result = await UserManager.RemovePasswordAsync(User.Identity.GetUserId());
            }
            else
            {
                result = await UserManager.RemoveLoginAsync(User.Identity.GetUserId(),
                    new UserLoginInfo(model.LoginProvider, model.ProviderKey));
            }

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // GET api/Account/ExternalLogin
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalCookie)]
        [AllowAnonymous]
        [Route("ExternalLogin", Name = "ExternalLogin")]
        public async Task<IHttpActionResult> GetExternalLogin(string provider, string error = null)
        {
            if (error != null)
            {
                return Redirect(Url.Content("~/") + "#error=" + Uri.EscapeDataString(error));
            }

            if (!User.Identity.IsAuthenticated)
            {
                return new ChallengeResult(provider, this);
            }

            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            if (externalLogin == null)
            {
                return InternalServerError();
            }

            if (externalLogin.LoginProvider != provider)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                return new ChallengeResult(provider, this);
            }

            ApplicationUser user = await UserManager.FindAsync(new UserLoginInfo(externalLogin.LoginProvider,
                externalLogin.ProviderKey));

            bool hasRegistered = user != null;

            if (hasRegistered)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                
                 ClaimsIdentity oAuthIdentity = await user.GenerateUserIdentityAsync(UserManager,
                    OAuthDefaults.AuthenticationType);
                ClaimsIdentity cookieIdentity = await user.GenerateUserIdentityAsync(UserManager,
                    CookieAuthenticationDefaults.AuthenticationType);

                AuthenticationProperties properties = ApplicationOAuthProvider.CreateProperties(user.UserName);
                Authentication.SignIn(properties, oAuthIdentity, cookieIdentity);
            }
            else
            {
                IEnumerable<Claim> claims = externalLogin.GetClaims();
                ClaimsIdentity identity = new ClaimsIdentity(claims, OAuthDefaults.AuthenticationType);
                Authentication.SignIn(identity);
            }

            return Ok();
        }

        // GET api/Account/ExternalLogins?returnUrl=%2F&generateState=true
        [AllowAnonymous]
        [Route("ExternalLogins")]
        public IEnumerable<ExternalLoginViewModel> GetExternalLogins(string returnUrl, bool generateState = false)
        {
            IEnumerable<AuthenticationDescription> descriptions = Authentication.GetExternalAuthenticationTypes();
            List<ExternalLoginViewModel> logins = new List<ExternalLoginViewModel>();

            string state;

            if (generateState)
            {
                const int strengthInBits = 256;
                state = RandomOAuthStateGenerator.Generate(strengthInBits);
            }
            else
            {
                state = null;
            }

            foreach (AuthenticationDescription description in descriptions)
            {
                ExternalLoginViewModel login = new ExternalLoginViewModel
                {
                    Name = description.Caption,
                    Url = Url.Route("ExternalLogin", new
                    {
                        provider = description.AuthenticationType,
                        response_type = "token",
                        client_id = Startup.PublicClientId,
                        redirect_uri = new Uri(Request.RequestUri, returnUrl).AbsoluteUri,
                        state = state
                    }),
                    State = state
                };
                logins.Add(login);
            }

            return logins;
        }

        // POST api/Account/Register
        [AllowAnonymous]
        [Route("Register")]
        public async Task<IHttpActionResult> Register(RegisterBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new ApplicationUser() { UserName = model.Email, Email = model.Email };

            IdentityResult result = await UserManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }


        [Route("DeleteRole")]
        [HttpGet]
        [Authorize]
        public async Task<IHttpActionResult> DeleteRole([FromUri] String property1)
        {


            var role = await this.AppRoleManager.FindByNameAsync(property1);

            if (role != null)
            {
                IdentityResult result = await this.AppRoleManager.DeleteAsync(role);

                if (!result.Succeeded)
                {
                    return GetErrorResult(result);
                }

                return Ok();
            }

            return NotFound();

        }

        [AllowAnonymous]
        [Route("CreateRole")]
        [HttpPost]
        public async Task<IHttpActionResult> CreateRole(GetMenu model)
        {
            var pp = "";
            var db4 = new ApplicationDbContext();
            var role = new IdentityRole { Name = model.bb.Name };

            var result = await this.AppRoleManager.CreateAsync(role);

            if (!result.Succeeded)
            {


                return GetErrorResult(result);
            }

            else
            {
                // var _db = new ApplicationDbContext();
                foreach (var pp2 in model.cc)
                {
                    var dd = model.bb;
                    // var ccd = (from c in db4.RolesPriviledges where c.RoleName == pp2.RoleName select c).ToList();
                    var ccd = (from c in db4.RolesPriviledges where c.RoleName == dd.Name select c).ToList();

                    if (ccd.Count > 0)
                    {
                        db4.RolesPriviledges.RemoveRange(ccd);
                        db4.SaveChanges();

                    }


                }

                foreach (var pp2 in model.cc)
                {
                    if (pp2.CreateNew == null)
                    {
                        pp2.CreateNew = "false";

                    }

                    if (pp2.DeleteNew == null)
                    {
                        pp2.DeleteNew = "false";

                    }

                    if (pp2.UpadateNew == null)
                    {
                        pp2.UpadateNew = "false";

                    }
                    if (pp2.View == null)
                    {
                        pp2.View = "false";

                    }

                    db4.RolesPriviledges.Add(pp2);


                }

                db4.SaveChanges();
            }


            return Ok();



        }


        [Authorize]
        [Route("GetAllRoles2")]
        [HttpGet]
        public List<String> GetAllRoles2()
        {
            var _db = new ApplicationDbContext();
            _db.Configuration.ProxyCreationEnabled = false;

            var pp = System.Web.HttpContext.Current.Request["RegisterBindingModel"];

            // ProductParam foo = Newtonsoft.Json.JsonConvert.DeserializeObject<ProductParam>(pp) as ProductParam;

            //   int vproductId = Convert.ToInt32(foo.ProductId);

            string currentUserId = User.Identity.GetUserId();
            List<String> dd = new List<String>();
            dd.Add(currentUserId);

            // var ccd = (from c in _db.Roles select c.Name).ToList();





            return dd;
        }


        [Route("GetRoles3")]
        [Authorize]

        public IList<String> GetRoles3([FromUri] String property1)
        {
            var _db = new ApplicationDbContext();

            ApplicationUser vv2 = UserManager.FindByEmail(property1);



            // string currentUserId = User.Identity.GetUserId();

            IList<String> vv = UserManager.GetRoles(vv2.Id);





            return vv;
        }


        [Authorize]
        [Route("AssignUserRole")]
        [HttpPost]
        public async Task<IHttpActionResult> AssignUserRole(UserRole model)
        //public async Task<HttpResponseMessage>  Register2()
        {


            //  ApplicationUser vv2 = UserManager.FindByEmail(model.username);



            // string currentUserId = User.Identity.GetUserId();

            //IList<String> vv3 = UserManager.GetRoles(vv2.Id);
            //if (vv3.Count > 0)
            //{
            //    UserManager.RemoveFromRoles(vv2.Id, vv3.ToArray());
            //}

            //foreach (var xxx in vv3)
            //{

            //    DeleteRole44(xxx);
            //}



            ApplicationUser vv = await UserManager.FindByEmailAsync(model.username);




            IdentityResult result = await UserManager.AddToRoleAsync(vv.Id, model.rolename);



            return Ok();

        }



        [Route("GetLoginToken2")]
        [AllowAnonymous]
        //  [Authorize]
        [HttpPost]

        public JObject GetLoginToken2(PostUser pp)



        //  public IHttpActionResult GetLoginToken2(PostUser pp)
        {
            var db4 = new ApplicationDbContext();
            db4.Configuration.ProxyCreationEnabled = false;
            try
            {
                ApplicationUser ds = UserManager.FindByEmail(pp.username);

                registration vreg = null;
                bool da = false;
                if (ds != null)
                {

                    var currentUserId = ds.Id;
                    var currentUser = db4.Users.FirstOrDefault(x => x.Id == currentUserId);

                    

                  //  else
                   // {
                      //  var Reguser = (from c in db4.registrations where c.Email == pp.username select c).FirstOrDefault();
                      //  vreg = Reguser;
                        // var Reguser = (from db4.;
                        da = UserManager.CheckPassword(ds, pp.password);

                        if (da)
                        {
                           // var identity = new BasicAuthenticationIdentity(pp.username, pp.password);
                           // var principal = new GenericPrincipal(identity, null);

                            //Thread.CurrentPrincipal = principal;
                            //if (HttpContext.Current != null)
                            //{
                            //    HttpContext.Current.User = principal;



                            //}
                            var ww = GetToken(pp.username, pp.password);
                      //  vreg.Token = ww;
                        return ww;





                            //  var ww = GetToken(pp.username, pp.password);

                            //  vreg.Token = ww;

                        }

                        else
                        {
                            JObject token = new JObject(new JProperty("error_description", "Invalid Username / Password"));
                        // vreg.Token = token;
                       // vreg.Token = token;
                        return token;

                        }

                   // }







                }

                else
                {
                    // add code 

                    JObject token = new JObject(new JProperty("error_description", "Invalid Username / Password"));
                  //  vreg.Token = token;

                    return token;

                }

                //  vreg = Login(pp.password, pp.username);

                //if (vreg.Email != null) {


                //    if (ds != null)
                //    {
                //        bool da = UserManager.CheckPassword(ds, "1111");

                //    }

                //    try
                //    {
                //       var  RoleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(new ApplicationDbContext()));

                //        UserManager.AddToRole(ds.Id, "Admin");

                //    }

                //    catch(Exception ee)
                //    {

                //        var dda = ee.Message;
                //    }
                //try
                //{

                //    var ccd = (from c in db4.registrations select c.Email).Distinct().ToList();



                //    foreach (var ccp in ccd)
                //    {
                //        var user = new Model2.ApplicationUser() { UserName = ccp, Email = ccp };

                //        IdentityResult result = UserManager.Create(user, "1111");

                //    }

                //}

                //catch (Exception ee)
                //{

                //    var ddx = ee.Message;
                //}



                //var ddf = UserManager.GetRoles(ds.Id).ToArray();
                //int vcount = 0;
                //var lf = "{";
                //foreach (var kk in ddf)
                //{
                //    if (vcount != ddf.Length - 1)
                //    {
                //        var ddx = string.Format("\"{0}\"", kk);
                //        lf = lf + ddx + ",";

                //    }

                //    else
                //    {
                //        var ddx = string.Format("\"{0}\"", kk);
                //        lf = lf + ddx + "}";
                //    }

                //    vcount = vcount + 1;

                //}

                // var ddf3 = ddf.ToString();

                //  var ccp = string.Join(" ,", ddf.ToArray()); ;


                //            var ccd = (from c in db4.RolesPriviledges
                //                       where
                //ddf.Any(x => x == c.RoleName)
                //                       select c).ToList();
                //            ;

                //            vreg.Access2 = ccd;




               // return vreg;

                // return ww;

                //  Model2.ApplicationUser ds = UserManager.FindByName(username);

                //  return Ok();

            }

            catch (Exception ee)
            {

                var pp2 = ee.Message;

                return null;
            }

        }

        public JObject GetToken(string userName, string password)
        {
            ClaimsIdentity oAuthIdentity = new ClaimsIdentity(Startup.OAuthOptions.AuthenticationType);

            ApplicationUser ds = UserManager.FindByEmail(userName);

            var ppx = User.Identity.GetUserId();
            oAuthIdentity.AddClaim(new Claim(ClaimTypes.Name, ds.UserName));
            oAuthIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, ds.Id));

            AuthenticationTicket ticket = new AuthenticationTicket(oAuthIdentity, new AuthenticationProperties());

            DateTime currentUtc = DateTime.UtcNow;
            ticket.Properties.IssuedUtc = currentUtc;
            ticket.Properties.ExpiresUtc = currentUtc.Add(TimeSpan.FromDays(365));

            string accessToken = Startup.OAuthOptions.AccessTokenFormat.Protect(ticket);
            Request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);



            // Create the response building a JSON object that mimics exactly the one issued by the default /Token endpoint
            JObject token = new JObject(
                new JProperty("userName", ds.UserName),
                new JProperty("userId", ds.Id),
                new JProperty("access_token", accessToken),
                new JProperty("token_type", "bearer"),
                new JProperty("expires_in", TimeSpan.FromDays(365).TotalSeconds.ToString()),
                new JProperty("issued", currentUtc.ToString("ddd, dd MMM yyyy HH':'mm':'ss 'GMT'")),
                new JProperty("expires", currentUtc.Add(TimeSpan.FromDays(1)).ToString("ddd, dd MMM yyyy HH:mm:ss 'GMT'"))
            );

            //comment by me 

            return token;

        }


        [Route("GetTopMenu")]
        [AllowAnonymous]
        [HttpGet]
        public List<TopMenu> GetTopMenu()
        {
            var _db = new ApplicationDbContext();

            // string currentUserId = User.Identity.GetUserId();
            //  IdentityRole cc = new IdentityRole();
            var ccd = (from c in _db.TopMenu select c).ToList();

            //   ApplicationUser currentUser = _db.Users.FirstOrDefault(x => x.Id == currentUserId);





            return ccd;
        }


        [Route("GetTopMenu2")]
        [AllowAnonymous]
        [HttpGet]
        public List<RolesPriviledges> GetTopMenu2([FromUri] String property1)
        {
            var db4 = new ApplicationDbContext();

            // string currentUserId = User.Identity.GetUserId();
            //  IdentityRole cc = new IdentityRole();
            var ccd = (from c in db4.RolesPriviledges
                           //  join p in db4.TopMenu    on new { a = c.Menu_Code } equals new { a = p.Menu_Code }
                       join p in db4.TopMenu on new { a = c.Menu_Code } equals new { a = p.Menu_Code }
                      into ps
                       from p in ps.DefaultIfEmpty()
                       where (c.RoleName == property1)

                       select new { p.Menu_Name, c.CreateNew, c.DeleteNew, c.UpadateNew, c.View, c.RoleName }).ToList();

            List<RolesPriviledges> dp = new List<RolesPriviledges>();
            foreach (var ddp in ccd)
            {
                RolesPriviledges pp2 = new RolesPriviledges();
                pp2.CreateNew = ddp.CreateNew;
                pp2.DeleteNew = ddp.DeleteNew;
                pp2.Menu_Code = ddp.Menu_Name;
                pp2.UpadateNew = ddp.UpadateNew;
                pp2.View = ddp.View;
                pp2.RoleName = ddp.RoleName;
                dp.Add(pp2);

            }

            //   ApplicationUser currentUser = _db.Users.FirstOrDefault(x => x.Id == currentUserId);





            return dp;
        }


        public String GetMenuName(string menucode)
        {
            var db4 = new ApplicationDbContext();
            var ccd = (from c in db4.TopMenu where c.Menu_Name == menucode select c).FirstOrDefault();
            return ccd.Menu_Code;
        }

        [Authorize]
        [Route("CreateRole2")]
        [HttpPost]
        public async Task<IHttpActionResult> CreateRole2(GetMenu model)
        {
            var pp = "";

            // DeletePriveleges(model.bb.Name);
            var db4 = new ApplicationDbContext();

            // var _db = new ApplicationDbContext();
            var dc = model.bb;
            foreach (var pp2 in model.cc)
            {
                var ccd = (from c in db4.RolesPriviledges where c.RoleName == dc.Name select c).ToList();

                if (ccd.Count > 0)
                {
                    db4.RolesPriviledges.RemoveRange(ccd);
                    db4.SaveChanges();

                }


            }
            foreach (var pp2 in model.cc)
            {
                if (pp2.CreateNew == null)
                {
                    pp2.CreateNew = "false";

                }

                if (pp2.DeleteNew == null)
                {
                    pp2.DeleteNew = "false";

                }

                if (pp2.UpadateNew == null)
                {
                    pp2.UpadateNew = "false";

                }
                if (pp2.View == null)
                {
                    pp2.View = "false";

                }
                pp2.Menu_Code = GetMenuName(pp2.Menu_Code);
                db4.RolesPriviledges.Add(pp2);


            }
            try
            {
                db4.SaveChanges();

            }

            catch (Exception ee)
            {
                var dx = ee.Message;
            }



            return Ok();



        }


       


        [Route("GetRoles")]
        [AllowAnonymous]
        public List<String> GetRoles()
        {
            var _db = new ApplicationDbContext();

            string currentUserId = User.Identity.GetUserId();
            IdentityRole cc = new IdentityRole();
            var ccd = (from c in _db.Roles select c.Name).ToList();


            //   ApplicationUser currentUser = _db.Users.FirstOrDefault(x => x.Id == currentUserId);





            return ccd;
        }


        [Route("GetContent")]
        [AllowAnonymous]
        public List<NewsTable> GetContent()
        {
            var _db = new ApplicationDbContext();

           // string currentUserId = User.Identity.GetUserId();
           // IdentityRole cc = new IdentityRole();
            var ccd = (from c in _db.Books select c ).ToList();


            //   ApplicationUser currentUser = _db.Users.FirstOrDefault(x => x.Id == currentUserId);





            return ccd;
        }



        [Route("UploadContent")]
        [AllowAnonymous]
        [HttpPost]
        public IHttpActionResult UploadContent(NewsTable dd2)
        {

            var _db = new ApplicationDbContext();
            _db.Configuration.ProxyCreationEnabled = false;

           // NewsTable dd = new NewsTable();

           // dd.Headline = property1;
           // dd.NewsContent = property2;
            dd2.Date_Added = DateTime.Now;
          //  dd2.Userid = "ozotony@yahoo.com";
            dd2.Status = "Pending";
            _db.Books.Add(dd2);
            _db.SaveChanges();

            return Ok();

        }


        [Route("GetPendingContent")]
        [AllowAnonymous]
        [HttpGet]
        public List<NewsTable>  GetPendingContent()
        {
            var _db = new ApplicationDbContext();
            _db.Configuration.ProxyCreationEnabled = false;
           


            var kk = (from c in _db.Books


                      where c.Status == "Pending" 
                      select c).ToList();

            //  IdentityUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());





            return kk;

        }

        [Route("GetPendingContent2")]
        [AllowAnonymous]
        [HttpGet]
        public NewsTable GetPendingContent2([FromUri] String property1)
        {
            var _db = new ApplicationDbContext();
            _db.Configuration.ProxyCreationEnabled = false;

            var dd = Convert.ToInt32(property1);

            var kk = (from c in _db.Books


                      where c.Status == "Pending" && c.NewsID == dd
                      select c).FirstOrDefault();

            //  IdentityUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());





            return kk;

        }


        [Route("GetEmailExist")]
        [AllowAnonymous]
        [HttpGet]
        public Int32 GetEmailExist([FromUri] String property1)
        {
            var _db = new ApplicationDbContext();
            _db.Configuration.ProxyCreationEnabled = false;

          //  var dd = Convert.ToInt32(property1);

            var kk = (from c in _db.Users


                      where c.Email == property1
                      select c).Count();

            //  IdentityUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());





            return kk;

        }


        [Route("GetUserCount")]
        [AllowAnonymous]
        [HttpGet]
        public async Task<Int32> GetUserCount([FromUri] String property1)
        {
            var _db = new ApplicationDbContext();
            _db.Configuration.ProxyCreationEnabled = false;

            //  Int32 pp = Convert.ToInt32(property1);


            Int32 kk = (from c in _db.Users where c.UserName == property1 select c).Count();





            return kk;
        }


        [AllowAnonymous]
        [Route("Register2")]
        [HttpPost]

        public async Task<IHttpActionResult> Register2()
        {

            var contentType = Request.Content.Headers.ContentType.MediaType;
            var pp = System.Web.HttpContext.Current.Request["RegisterBindingModel"];

            RegisterBindingModel foo = Newtonsoft.Json.JsonConvert.DeserializeObject<RegisterBindingModel>(pp) as RegisterBindingModel;



            var httpRequest = HttpContext.Current.Request;






            var user = new ApplicationUser() { UserName = foo.Email, Email = foo.Email,  First_Name = foo.First_Name, Surname = foo.Surname, };
            foo.Password = foo.Password;

            IdentityResult result = await UserManager.CreateAsync(user, foo.Password);

            if (!result.Succeeded)
            {

                return GetErrorResult(result);
            }
            //  return   Request.CreateErrorResponse(HttpStatusCode.Created,
            //  sendemail(foo.Email, foo.Email);  

          //  sendemail2(foo.Email, foo.Email, foo.Password);
            return Ok();
        }
        // POST api/Account/RegisterExternal
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("RegisterExternal")]
        public async Task<IHttpActionResult> RegisterExternal(RegisterExternalBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var info = await Authentication.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return InternalServerError();
            }

            var user = new ApplicationUser() { UserName = model.Email, Email = model.Email };

            IdentityResult result = await UserManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            result = await UserManager.AddLoginAsync(user.Id, info.Login);
            if (!result.Succeeded)
            {
                return GetErrorResult(result); 
            }
            return Ok();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _userManager != null)
            {
                _userManager.Dispose();
                _userManager = null;
            }

            base.Dispose(disposing);
        }

        #region Helpers

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }

        private IHttpActionResult GetErrorResult(IdentityResult result)
        {
            if (result == null)
            {
                return InternalServerError();
            }

            if (!result.Succeeded)
            {
                if (result.Errors != null)
                {
                    foreach (string error in result.Errors)
                    {
                        ModelState.AddModelError("", error);
                    }
                }

                if (ModelState.IsValid)
                {
                    // No ModelState errors are available to send, so just return an empty BadRequest.
                    return BadRequest();
                }

                return BadRequest(ModelState);
            }

            return null;
        }

        private class ExternalLoginData
        {
            public string LoginProvider { get; set; }
            public string ProviderKey { get; set; }
            public string UserName { get; set; }

            public IList<Claim> GetClaims()
            {
                IList<Claim> claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.NameIdentifier, ProviderKey, null, LoginProvider));

                if (UserName != null)
                {
                    claims.Add(new Claim(ClaimTypes.Name, UserName, null, LoginProvider));
                }

                return claims;
            }

            public static ExternalLoginData FromIdentity(ClaimsIdentity identity)
            {
                if (identity == null)
                {
                    return null;
                }

                Claim providerKeyClaim = identity.FindFirst(ClaimTypes.NameIdentifier);

                if (providerKeyClaim == null || String.IsNullOrEmpty(providerKeyClaim.Issuer)
                    || String.IsNullOrEmpty(providerKeyClaim.Value))
                {
                    return null;
                }

                if (providerKeyClaim.Issuer == ClaimsIdentity.DefaultIssuer)
                {
                    return null;
                }

                return new ExternalLoginData
                {
                    LoginProvider = providerKeyClaim.Issuer,
                    ProviderKey = providerKeyClaim.Value,
                    UserName = identity.FindFirstValue(ClaimTypes.Name)
                };
            }
        }

        private static class RandomOAuthStateGenerator
        {
            private static RandomNumberGenerator _random = new RNGCryptoServiceProvider();

            public static string Generate(int strengthInBits)
            {
                const int bitsPerByte = 8;

                if (strengthInBits % bitsPerByte != 0)
                {
                    throw new ArgumentException("strengthInBits must be evenly divisible by 8.", "strengthInBits");
                }

                int strengthInBytes = strengthInBits / bitsPerByte;

                byte[] data = new byte[strengthInBytes];
                _random.GetBytes(data);
                return HttpServerUtility.UrlTokenEncode(data);
            }
        }

        #endregion
    }
}
