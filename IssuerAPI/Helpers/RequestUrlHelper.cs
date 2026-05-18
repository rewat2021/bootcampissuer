namespace IssuerAPI.Helpers
{
    public class RequestUrlHelper
    {
        public static string GetBaseUrl(HttpContext context)
        {
            var scheme = context.Request.Headers["X-Forwarded-Proto"].FirstOrDefault()
                         ?? context.Request.Scheme;

            var host = context.Request.Headers["X-Forwarded-Host"].FirstOrDefault()
                       ?? context.Request.Host.Value;

            return $"{scheme}://{host}";
        }
    }
}
