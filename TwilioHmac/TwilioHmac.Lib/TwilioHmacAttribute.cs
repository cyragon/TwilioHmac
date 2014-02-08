using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using System.Collections.Specialized;
using System.IO;
using System.Net;

namespace cyragon.TwilioHmac
{
    public class TwilioHmacAttribute : ActionFilterAttribute
    {
        private string AuthToken { get; set; }

        public TwilioHmacAttribute(string authToken)
        {
            AuthToken = authToken;
        }

        public override void OnActionExecuting(HttpActionContext actionContext)
        {
            bool validRequest = false;

            if (actionContext.Request.Headers.Contains("X-Twilio-Signature"))
            {
                var value = new StringBuilder();

                value.Append(actionContext.Request.RequestUri.AbsoluteUri);

                // If the request is a POST, take all of the POST parameters and sort them alphabetically.
                if (actionContext.Request.Method == HttpMethod.Post)
                {
                    actionContext.Request.Content.ReadAsStreamAsync().ContinueWith(t => t.Result.Seek(0, SeekOrigin.Begin)).Wait();
                    // read the stream
                    var form = actionContext.Request.Content.ReadAsFormDataAsync().Result;
                    // reset the stream for the target controller, or anyone else that want's it.
                    actionContext.Request.Content.ReadAsStreamAsync().ContinueWith(t => t.Result.Seek(0, SeekOrigin.Begin)).Wait();

                    // Iterate through that sorted list of POST parameters, and append the variable name and value (with no delimiters) to the end of the URL string
                    var sortedKeys = form.AllKeys.OrderBy(k => k, StringComparer.Ordinal).ToList();
                    foreach (var key in sortedKeys)
                    {
                        value.Append(key);
                        value.Append(form[key]);
                    }
                }

                // Sign the resulting value with HMAC-SHA1 using your AuthToken as the key (remember, your AuthToken's case matters!).
                var sha1 = new HMACSHA1(Encoding.UTF8.GetBytes(AuthToken));
                var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(value.ToString()));

                // Base64 encode the hash
                var encoded = Convert.ToBase64String(hash);

                // Compare your hash to ours, submitted in the X-Twilio-Signature header. If they match, then you're good to go.
                var sig = actionContext.Request.Headers.GetValues("X-Twilio-Signature").First();

                validRequest = (sig == encoded);
            }

            if (!validRequest)
            {
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                response.Content = new StringContent("Twilio signature vaildation failed.");
                actionContext.Response = response;
            }

            base.OnActionExecuting(actionContext);
        }
    }
}

