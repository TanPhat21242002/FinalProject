using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MongoAuthenticatorAPI.Dtos;
using MongoAuthenticatorAPI.Models;

namespace MongoAuthenticatorAPI.Controllers
{
	[Route("api/v1/validate")]
	[ApiController]
	public class ValuesController : ControllerBase
	{

		[HttpPost]
		[Route("token")]
		public IActionResult ValToken([FromBody] TokenDTO token)
		{
			return Ok(token);
		}
	}
}
