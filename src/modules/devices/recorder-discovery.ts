import { BadRequestException } from "@nestjs/common";
import { cameraHttp, privateCameraHost } from "./recorder-http";

export function recorderDiscoveryHosts(cidr: string) {
  const [address, prefix, extra] = cidr.split("/");
  const bits = Number(prefix);
  try {
    privateCameraHost(address);
    if (extra !== undefined || !/^(?:2[4-9]|3[0-2])$/.test(prefix ?? "")) throw new Error();
  } catch {
    throw new BadRequestException("یک شبکهٔ IPv4 خصوصی با پیشوند ۲۴ تا ۳۲ وارد کنید.");
  }
  const parts = address.split(".").map(Number);
  const size = 2 ** (32 - bits);
  const start = Math.floor(parts[3] / size) * size;
  const first = size > 2 ? 1 : 0;
  const count = size > 2 ? size - 2 : size;
  return Array.from({ length: count }, (_, index) =>
    [...parts.slice(0, 3), start + first + index].join("."),
  );
}

export async function discoverRecorders(cidr: string, port: number, https: boolean) {
  const hosts = recorderDiscoveryHosts(cidr);
  const matches: { host: string; port: number; https: boolean }[] = [];
  for (let index = 0; index < hosts.length; index += 32) {
    await Promise.all(
      hosts.slice(index, index + 32).map(async (host) => {
        try {
          const response = await cameraHttp(
            new URL(`${https ? "https" : "http"}://${host}:${port}/onvif/device_service`),
            {
              method: "POST",
              headers: { "Content-Type": "application/soap+xml; charset=utf-8" },
              body: '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>',
              timeout: 900,
              maxBytes: 16384,
            },
          );
          const auth = response.headers["www-authenticate"] ?? "";
          const body = response.body.toString("utf8");
          if (
            (response.status === 401 && /realm="[^"]*onvif/i.test(auth)) ||
            (response.status <= 500 &&
              /<(?:[\w.-]+:)?(?:Envelope|GetDeviceInformationResponse)\b/i.test(body) &&
              /onvif\.org/i.test(body))
          )
            matches.push({ host, port, https });
        } catch {
          // An unavailable address does not prevent scanning the rest of the subnet.
        }
      }),
    );
  }
  return matches.sort((left, right) =>
    left.host.localeCompare(right.host, undefined, { numeric: true }),
  );
}
