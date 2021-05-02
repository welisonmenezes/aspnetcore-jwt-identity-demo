# Estudando o Identity do DotNet Core 5



## Dependências
Segue Pacotes de dependênicas usadas na demo:

```
<PackageReference Include="Microsoft.AspNetCore.Authorization" Version="5.0.0" />
<PackageReference Include="Microsoft.AspNetCore.Authentication" Version="2.2.0" />
<PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="5.0.0" />
<PackageReference Include="Microsoft.AspNetCore.Identity.EntityFrameworkCore" Version="5.0.0" />
<PackageReference Include="Microsoft.EntityFrameworkCore" Version="5.0.5" />
<PackageReference Include="Microsoft.EntityFrameworkCore.Design" Version="5.0.5" />
<PackageReference Include="Microsoft.EntityFrameworkCore.SqlServer" Version="5.0.5" />
<PackageReference Include="Microsoft.EntityFrameworkCore.Tools" Version="5.0.5" />
```



## API básica com Identity

Passo 1
Criar a classe de db context:

```
public class ApplicationDbContext : IdentityDbContext<User>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
    }
}
```


Passo 2
Adicionar serviço de db context na aplicação:

```
services.AddDbContext<ApplicationDbContext>(options =>
	options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));
```


Passo 3
Configurar a conection string no arquivo appsettings.json:

```
"ConnectionStrings": {
"DefaultConnection": "Server=DESKTOP-0KTTMSL;Database=TestIdentity;Trusted_Connection=True;"
},
```


Passo 4:
Criar o modelo de user:

```
public class User : IdentityUser
{
    // any custom attribute here
}
```


Passo 5: 
Adicionar o serviço de Identity na aplicação:

```
services.AddIdentity<User, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>();
```


Passo 6:
Configuar a aplicação a usar o authentication e o authorization

```
app.UseAuthentication();
app.UseAuthorization();
```


Passo 7:
Criar o controller de autenticação:

```
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly SignInManager<User> signInManager;
    private readonly UserManager<User> userManager;

    public AuthController(SignInManager<User> signInManager, UserManager<User> userManager)
    {
        this.signInManager = signInManager;
        this.userManager = userManager;
    }
}
```


Passo 8:
Criar view model da tela de cadastro:

```
public class RegisterUserViewModel
{
    [Required(ErrorMessage = "O Campo {0} é obrigatório.")]
    [EmailAddress(ErrorMessage = "O campo {0} deve ser um email válido.")]
    public string Email { get; set; }

    [Required(ErrorMessage = "O Campo {0} é obrigatório.")]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    [Compare("Password")]
    [DataType(DataType.Password)]
    public string ConfirmPassword { get; set; }
}
```


Passo 9:
Adicionar metodo de registrar novo usuário no AuthController:

```
[HttpPost("register")]
public async Task<ActionResult> Register(RegisterUserViewModel registerUser)
{
    if (!ModelState.IsValid) return BadRequest(ModelState.Values.SelectMany(e => e.Errors));

    User user = new()
    {
        UserName = registerUser.Email,
        Email = registerUser.Email,
        EmailConfirmed = true
    };

    var result = await userManager.CreateAsync(user, registerUser.Password);

    if (!result.Succeeded) return BadRequest(result.Errors);

    await signInManager.SignInAsync(user, false);

    return Ok();
}
```


Passo 10:
Criar view model da tela de login:

```
public class LoginUserViewModel
{
    [Required(ErrorMessage = "O Campo {0} é obrigatório.")]
    [EmailAddress(ErrorMessage = "O campo {0} deve ser um email válido.")]
    public string Email { get; set; }

    [Required(ErrorMessage = "O Campo {0} é obrigatório.")]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    public bool RememberMe { get; set; } = false;
}
```


Passo 11:
Criar metodo de login no AuthController:

```
[HttpPost("login")]
public async Task<ActionResult> Login(LoginUserViewModel loginUser)
{
    if (!ModelState.IsValid) return BadRequest(ModelState.Values.SelectMany(e => e.Errors));

    var result = await signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, loginUser.RememberMe, lockoutOnFailure: true);

    if (!result.Succeeded) return BadRequest("Login or Password invalid.");

    return Ok();
}
```


Passo 12:
Criar metodo de logout no AuthController:

```
[HttpPost("logout")]
public async Task<ActionResult> Logout()
{
    await signInManager.SignOutAsync();
    return Ok();
}
```



## Criar o banco de dados
Antes de rodar e testa a aplicação, é preciso criar as tabelas do Idenitiy no banco de dados.
Para criar as tabelas do Identity rode os seguintes comandos:

```
Add-Migration Identity

Update-Database
```



## Incluindo o JWT

 Passo 1:
 Adicionar a sessão AppSettins no arquivo appsettings.json:

```
"AppSettings": {
    "Secret": "your-secrete-hash-here",
    "Expiration": 2,
    "Emitter": "",
    "ValidIn":  "https://localhost"
}
 ```


Passo 2:
Criar classe de Settings para usar no JWT

```
public class AppSettings
{
    public string Secret { get; set; }
    public int Expiration { get; set; }
    public string Emitter { get; set; }
    public string ValidIn { get; set; }
}
 ```


Passo 3:
Configurar o serviço de authenticação para usar o JWT:

```
var appSettingnsSection = Configuration.GetSection("AppSettings");
services.Configure<AppSettings>(appSettingnsSection);
AppSettings appSettings = appSettingnsSection.Get<AppSettings>();
var key = Encoding.ASCII.GetBytes(appSettings.Secret);

services.AddAuthentication(x =>
{
    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(x =>
{
    x.RequireHttpsMetadata = true;
    x.SaveToken = true;
    x.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidAudience = appSettings.ValidIn,
        ValidIssuer = appSettings.Emitter
    };
});
```


Passo 4:
Modificar o AuthControler injetando o appSettings no seu construtor:

```
private readonly SignInManager<User> signInManager;
private readonly UserManager<User> userManager;
private readonly IOptions<AppSettings> appSettings;

public AuthController(SignInManager<User> signInManager, UserManager<User> userManager, IOptions<AppSettings> appSettings)
{
    this.signInManager = signInManager;
    this.userManager = userManager;
    this.appSettings = appSettings;
}
```


Passo 5:
Criar metodo que gera o token no AuthController:

```
private string GetToken(User user)
{
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.ASCII.GetBytes(appSettings.Value.Secret);

    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Issuer = appSettings.Value.Emitter,
        Audience = appSettings.Value.ValidIn,
        Expires = DateTime.UtcNow.AddHours(appSettings.Value.Expiration),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
        Subject = new ClaimsIdentity(new Claim[]
        {
            new Claim(ClaimTypes.Name, user.Email.ToString())
        })
    };

    return tokenHandler.WriteToken(tokenHandler.CreateToken(tokenDescriptor));
}
```


Passo 6:
Modificar o metodo Register do AuthController para funcionar com o JWT:

```
[HttpPost("register")]
public async Task<ActionResult> Register(RegisterUserViewModel registerUser)
{
    if (!ModelState.IsValid) return BadRequest(ModelState.Values.SelectMany(e => e.Errors));

    User user = new()
    {
        UserName = registerUser.Email,
        Email = registerUser.Email,
        EmailConfirmed = true
    };

    var result = await userManager.CreateAsync(user, registerUser.Password);

    if (!result.Succeeded) return BadRequest(result.Errors);

    return Ok(GetToken(user));
}
```


Passo 7:
Modificar o metodo Login do AuthController para funcionar com o JWT:

```
[HttpPost("login")]
public async Task<ActionResult> Login(LoginUserViewModel loginUser)
{
    if (!ModelState.IsValid) return BadRequest(ModelState.Values.SelectMany(e => e.Errors));

    var result = await signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, loginUser.RememberMe, lockoutOnFailure: true);

    if (!result.Succeeded) return BadRequest("Login or Password invalid.");

    User user = new()
    { 
        Email = loginUser.Email
    };

    return Ok(GetToken(user));
}
```


Passo 8:
Remover o metodo Logout, pois é só remover o token do frontend que o mesmo perde o acesso.