using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using MongoAuthenticatorAPI.Dtos;
using MongoDB.Bson.IO;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace MongoAuthenticatorAPI.Middlewares
{
	public class UserTokenValidation
	{
		private readonly RequestDelegate _next;
		private const string ApiKeyFromBodyFieldName = "jwtToken"; // Tên trường chứa API key trong body

		public UserTokenValidation(RequestDelegate next)
		{
			_next = next;
		}

		public async Task Invoke(HttpContext context)
		{

			if (!context.Request.Method.Equals("POST") && !context.Request.Method.Equals("PUT"))
			{
				// Chỉ xác thực API key cho các yêu cầu POST và PUT, bạn có thể điều chỉnh điều kiện này tùy theo yêu cầu của bạn
				await context.Response.WriteAsync("Invalid request.");
				return;
			}

			context.Request.EnableBuffering();

			// Đọc request body
			using (StreamReader reader = new StreamReader(
				context.Request.Body,
				encoding: Encoding.UTF8,
				detectEncodingFromByteOrderMarks: false,
				bufferSize: 1024,
				leaveOpen: true))
			{
				string requestBody = await reader.ReadToEndAsync();

				// Xử lý requestBody để lấy API key (đây là một ví dụ, bạn cần phải điều chỉnh tùy theo định dạng dữ liệu của bạn)

				if (string.IsNullOrEmpty(GetApiKeyFromBody(requestBody)))
				{
					context.Response.StatusCode = 401; // Unauthorized
					await context.Response.WriteAsync("API Key is missing or invalid.");
					return;
				}

				// Kiểm tra API key ở đây (ví dụ: so sánh với một danh sách các API key hợp lệ)
				if (!IsValidApiKey(GetApiKeyFromBody(requestBody)))
				{
					context.Response.StatusCode = 403; // Forbidden
					await context.Response.WriteAsync("Invalid API Key.");
					return;
				}

				// Đặt lại vị trí của stream cho request body để nó có thể được đọc lại sau này
				context.Request.Body.Position = 0;

				// Thêm API key vào context để sử dụng trong các xử lý tiếp theo
				context.Items["jwtToken"] = GetApiKeyFromBody(requestBody);
			}

			await _next(context);
		}

		private string? GetApiKeyFromBody(string requestBody)
		{
			// Đây là một phương pháp đơn giản để lấy API key từ body, bạn cần điều chỉnh dựa trên định dạng dữ liệu của bạn
			// Ví dụ: nếu dữ liệu được gửi dưới dạng JSON, bạn có thể sử dụng một thư viện JSON để phân tích cú pháp và trích xuất API key
			// Trong ví dụ này, giả sử requestBody là một chuỗi có dạng "api_key=value"

			var myJwt = JsonNode.Parse(requestBody);

			if(myJwt == null)
			{
				return null;
			}

			if(myJwt["token"] == null)
			{
				return null;
			}
			else
			{
				return myJwt?["token"]?.ToString();
			}
		}

		private bool IsValidApiKey(string apiKey)
		{
			// Việc kiểm tra tính hợp lệ của API key có thể được thực hiện tại đây
			// Ví dụ: so sánh với một danh sách các API key hợp lệ
			return YourApiKeyValidationLogic(apiKey);
		}

		private bool YourApiKeyValidationLogic(string apiKey)
		{
			// Thực hiện kiểm tra tính hợp lệ của API key ở đây
			// Ví dụ: so sánh với một danh sách các API key hợp lệ
			// Trong trường hợp này, tôi giả sử tất cả các API key là hợp lệ
			JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
			TokenValidationParameters validationParameters = new TokenValidationParameters();

			SecurityToken validatedToken;

			validationParameters.ValidIssuer = "https://localhost:5001";
			validationParameters.ValidAudience = "https://localhost:5001";
			validationParameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("1swek3u4uo2u4a6e"));
			try
			{
				ClaimsPrincipal principal = tokenHandler.ValidateToken(apiKey, validationParameters, out validatedToken);
			}catch (SecurityTokenValidationException ex)
			{
				return false;
			}

			Console.WriteLine(validatedToken);
			return true;
		}
	}
}
