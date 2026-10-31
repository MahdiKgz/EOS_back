import assert from "node:assert/strict";
import { createServer } from "node:net";
import { once } from "node:events";
import { randomBytes } from "node:crypto";
import { config } from "dotenv";
import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { DataSource } from "typeorm";
config({ quiet: true });

async function main() {
  const messages = [];
  const smtp = createServer(socket => {
    socket.write('220 localhost ESMTP\r\n');
    let buffer = '', data = false, lines = [];
    socket.on('data', chunk => {
      buffer += chunk.toString();
      while (buffer.includes('\n')) {
        const end = buffer.indexOf('\n');
        const line = buffer.slice(0, end).replace(/\r$/, ''); buffer = buffer.slice(end + 1);
        if (data) {
          if (line === '.') { messages.push(lines.join('\r\n')); lines = []; data = false; socket.write('250 accepted\r\n'); }
          else lines.push(line);
        } else if (/^EHLO|^HELO/.test(line)) socket.write('250 localhost\r\n');
        else if (/^DATA/.test(line)) { data = true; socket.write('354 end with dot\r\n'); }
        else if (/^QUIT/.test(line)) socket.end('221 bye\r\n');
        else socket.write('250 ok\r\n');
      }
    });
  });
  smtp.listen(0, '127.0.0.1'); await once(smtp, 'listening');
  process.env.SMTP_HOST = '127.0.0.1'; process.env.SMTP_PORT = String(smtp.address().port);
  process.env.JWT_SECRET = randomBytes(32).toString('hex');
  const { AppModule } = await import('../dist/app.module.js');
  const { AppUser } = await import('../dist/modules/users/user.entity.js');
  const app = await NestFactory.create(AppModule, { logger: false });
  app.setGlobalPrefix('api/v1'); app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
  const ids = [];
  try {
    await app.listen(0, '127.0.0.1');
    const base = (await app.getUrl()) + '/api/v1/auth/';
    const call = async (action, body, token) => {
      const response = await fetch(base + action, { method: body === undefined ? 'GET' : 'POST', headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
      return { status: response.status, body: await response.json() };
    };
    const username = 'verify_' + Date.now();
    const input = { username, displayName: 'کاربر آزمایشی', email: username + '@example.com', password: 'Valid-Password-4286' };
    assert.equal((await call('me')).status, 401);
    assert.equal((await call('register', { ...input, role: 'pl_admin' })).status, 400);
    const registration = await call('register', input);
    assert.equal(registration.status, 201); ids.push(registration.body.user.id);
    assert.equal(registration.body.user.role, 'co_employee');
    assert.equal('passwordHash' in registration.body.user, false);
    assert.equal((await call('register', input)).status, 409);
    assert.equal((await call('login', { username, password: 'wrong-password' })).status, 401);
    const login = await call('login', { username: username.toUpperCase(), password: input.password });
    assert.equal(login.status, 200); const token = login.body.accessToken;
    assert.equal((await call('me', undefined, token)).status, 200);
    const jwt = app.get(JwtService);
    const decoded = jwt.decode(token);
    const expired = await jwt.signAsync({ sub: decoded.sub, sid: decoded.sid }, { expiresIn: -10 });
    assert.equal((await call('me', undefined, expired)).status, 401);
    const forged = token.slice(0, -5) + 'xxxxx';
    assert.equal((await call('me', undefined, forged)).status, 401);
    assert.equal((await call('logout', {}, token)).status, 200);
    assert.equal((await call('me', undefined, token)).status, 401);
    const recovery = await call('forget-password', { email: input.email });
    assert.equal(recovery.status, 200); assert.equal(messages.length, 1);
    const anonymousRecovery = await call('forget-password', { email: 'missing_' + input.email });
    assert.equal(anonymousRecovery.status, 200); assert.equal(recovery.body.message, anonymousRecovery.body.message);
    const mail = messages[0];
    const raw = /Content-Transfer-Encoding: base64/i.test(mail)
      ? Buffer.from(mail.split('\r\n\r\n').slice(1).join('\r\n\r\n').replace(/\s/g, ''), 'base64').toString('utf8')
      : mail.replace(/=\r?\n/g, '').replace(/=3D/gi, '=');
    const resetToken = raw.match(/token=([a-f0-9]{64})/)?.[1]; assert.ok(resetToken, 'Reset email must contain a token');
    const secondLogin = await call('login', { username, password: input.password });
    assert.equal(secondLogin.status, 200);
    const reset = await call('reset-password', { token: resetToken, password: 'New-Password-5397' });
    assert.equal(reset.status, 200);
    assert.equal((await call('reset-password', { token: resetToken, password: 'Other-Password-5397' })).status, 400);
    assert.equal((await call('me', undefined, secondLogin.body.accessToken)).status, 401);
    assert.equal((await call('login', { username, password: input.password })).status, 401);
    assert.equal((await call('login', { username, password: 'New-Password-5397' })).status, 200);
    let last;
    for (let i = 0; i < 12; i++) last = await call('login', { username, password: 'incorrect' });
    assert.equal(last.status, 429);
    console.log('PASS: registration, default role, mass assignment rejection, duplicates, login, JWT signature/expiry, logout revocation, SMTP recovery, one-use reset, old-session revocation and rate limiting.');
  } finally {
    if (app.get(DataSource).isInitialized && ids.length) await app.get(DataSource).getRepository(AppUser).delete(ids);
    await app.close(); await new Promise(resolve => smtp.close(resolve));
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
