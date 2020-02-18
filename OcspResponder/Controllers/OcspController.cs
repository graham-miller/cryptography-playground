using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using OcspResponder.AspNetCore;
using OcspResponder.Core;

namespace OcspResponder.Controllers
{
    [Route("api/ocsp")]
    public class OcspController : Controller
    {
        public OcspController(IOcspResponder ocspResponder)
        {
            _ocspResponder = ocspResponder;
        }

        [HttpGet]
        public async Task<IActionResult> Get(string encoded)
        {
            var ocspHttpRequest = await Request.ToOcspHttpRequest();
            var ocspHttpResponse = await _ocspResponder.Respond(ocspHttpRequest);
            return new OcspActionResult(ocspHttpResponse);
        }

        [HttpPost]
        public async Task<IActionResult> Post()
        {
            var ocspHttpRequest = await Request.ToOcspHttpRequest();
            var ocspHttpResponse = await _ocspResponder.Respond(ocspHttpRequest);
            return new OcspActionResult(ocspHttpResponse);
        }

        private readonly IOcspResponder _ocspResponder;
    }
}