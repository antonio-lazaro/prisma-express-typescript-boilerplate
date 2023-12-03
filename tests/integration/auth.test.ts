import request from 'supertest';
import { faker } from '@faker-js/faker';
import httpStatus from 'http-status';
import httpMocks from 'node-mocks-http';
import moment from 'moment';
import bcrypt from 'bcryptjs';
import app from '../../src/app';
import config from '../../src/config/config';
import auth from '../../src/middlewares/auth';
import { emailService, tokenService } from '../../src/services';
import ApiError from '../../src/utils/ApiError';
import setupTestDB from '../utils/setupTestDb';
import { describe, beforeEach, test, expect, jest } from '@jest/globals';
import { userOne, admin, insertUsers } from '../fixtures/user.fixture';
import { Role, TokenType, User } from '@prisma/client';
import prisma from '../../src/client';
import { roleRights } from '../../src/config/roles';

setupTestDB();

describe('Auth routes', () => {
  describe('POST /v1/auth/register', () => {
    let newUser: { email: string; password: string };
    beforeEach(() => {
      newUser = {
        email: faker.internet.email().toLowerCase(),
        password: 'password1'
      };
    });

    test('should return 201 and successfully register user if request data is ok', async () => {
      const res = await request(app)
        .post('/v1/auth/register')
        .send(newUser)
        .expect(httpStatus.CREATED);

      expect(res.body.user).not.toHaveProperty('password');
      expect(res.body.user).toEqual({
        id: expect.anything(),
        name: null,
        email: newUser.email,
        role: Role.USER,
        isEmailVerified: false
      });

      const dbUser = await prisma.user.findUnique({ where: { id: res.body.user.id } });
      expect(dbUser).toBeDefined();
      expect(dbUser?.password).not.toBe(newUser.password);
      expect(dbUser).toMatchObject({
        name: null,
        email: newUser.email,
        role: Role.USER,
        isEmailVerified: false
      });

      expect(res.body.tokens).toEqual({
        access: { token: expect.anything(), expires: expect.anything() },
        refresh: { token: expect.anything(), expires: expect.anything() }
      });
    });

    test('should return 400 error if email is invalid', async () => {
      newUser.email = 'invalidEmail';

      await request(app).post('/v1/auth/register').send(newUser).expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if email is already used', async () => {
      await insertUsers([userOne]);
      newUser.email = userOne.email;

      await request(app).post('/v1/auth/register').send(newUser).expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if password length is less than 8 characters', async () => {
      newUser.password = 'passwo1';

      await request(app).post('/v1/auth/register').send(newUser).expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if password does not contain both letters and numbers', async () => {
      newUser.password = 'password';

      await request(app).post('/v1/auth/register').send(newUser).expect(httpStatus.BAD_REQUEST);

      newUser.password = '11111111';

      await request(app).post('/v1/auth/register').send(newUser).expect(httpStatus.BAD_REQUEST);
    });
  });

  describe('POST /v1/auth/login', () => {
    test('should return 200 and login user if email and password match', async () => {
      await insertUsers([userOne]);
      const loginCredentials = {
        email: userOne.email,
        password: userOne.password
      };

      const res = await request(app)
        .post('/v1/auth/login')
        .send(loginCredentials)
        .expect(httpStatus.OK);

      expect(res.body.user).toMatchObject({
        id: expect.anything(),
        name: userOne.name,
        email: userOne.email,
        role: userOne.role,
        isEmailVerified: userOne.isEmailVerified
      });

      expect(res.body.user).toEqual(expect.not.objectContaining({ password: expect.anything() }));

      expect(res.body.tokens).toEqual({
        access: { token: expect.anything(), expires: expect.anything() },
        refresh: { token: expect.anything(), expires: expect.anything() }
      });
    });

    test('should return 401 error if there are no users with that email', async () => {
      const loginCredentials = {
        email: userOne.email,
        password: userOne.password
      };

      const res = await request(app)
        .post('/v1/auth/login')
        .send(loginCredentials)
        .expect(httpStatus.UNAUTHORIZED);

      expect(res.body).toEqual({
        code: httpStatus.UNAUTHORIZED,
        message: 'Incorrect email or password'
      });
    });

    test('should return 401 error if password is wrong', async () => {
      await insertUsers([userOne]);
      const loginCredentials = {
        email: userOne.email,
        password: 'wrongPassword1'
      };

      const res = await request(app)
        .post('/v1/auth/login')
        .send(loginCredentials)
        .expect(httpStatus.UNAUTHORIZED);

      expect(res.body).toEqual({
        code: httpStatus.UNAUTHORIZED,
        message: 'Incorrect email or password'
      });
    });
  });

  describe('POST /v1/auth/logout', () => {
    test('should return 204 if refresh token is valid', async () => {
      await insertUsers([userOne]);
      const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(dbUserOne.id, expires, TokenType.REFRESH);
      await tokenService.saveToken(refreshToken, dbUserOne.id, expires, TokenType.REFRESH);

      await request(app)
        .post('/v1/auth/logout')
        .send({ refreshToken })
        .expect(httpStatus.NO_CONTENT);

      const dbRefreshTokenData = await prisma.token.findFirst({ where: { token: refreshToken } });
      expect(dbRefreshTokenData).toBe(null);
    });

    test('should return 400 error if refresh token is missing from request body', async () => {
      await request(app).post('/v1/auth/logout').send().expect(httpStatus.BAD_REQUEST);
    });

    test('should return 404 error if refresh token is not found in the database', async () => {
      await insertUsers([userOne]);
      const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(dbUserOne.id, expires, TokenType.REFRESH);

      await request(app)
        .post('/v1/auth/logout')
        .send({ refreshToken })
        .expect(httpStatus.NOT_FOUND);
    });

    test('should return 404 error if refresh token is blacklisted', async () => {
      await insertUsers([userOne]);
      const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(dbUserOne.id, expires, TokenType.REFRESH);
      await tokenService.saveToken(refreshToken, dbUserOne.id, expires, TokenType.REFRESH, true);

      await request(app)
        .post('/v1/auth/logout')
        .send({ refreshToken })
        .expect(httpStatus.NOT_FOUND);
    });
  });

  describe('POST /v1/auth/refresh-tokens', () => {
    test('should return 200 and new auth tokens if refresh token is valid', async () => {
      await insertUsers([userOne]);
      const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(dbUserOne.id, expires, TokenType.REFRESH);
      await tokenService.saveToken(refreshToken, dbUserOne.id, expires, TokenType.REFRESH);

      const res = await request(app)
        .post('/v1/auth/refresh-tokens')
        .send({ refreshToken })
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        access: { token: expect.anything(), expires: expect.anything() },
        refresh: { token: expect.anything(), expires: expect.anything() }
      });

      const dbRefreshTokenData = await prisma.token.findFirst({
        where: { token: res.body.refresh.token },
        select: {
          type: true,
          userId: true,
          blacklisted: true
        }
      });
      expect(dbRefreshTokenData).toMatchObject({
        type: TokenType.REFRESH,
        userId: dbUserOne.id,
        blacklisted: false
      });

      const dbRefreshTokenCount = await prisma.token.count();
      expect(dbRefreshTokenCount).toBe(1);
    });

    test('should return 400 error if refresh token is missing from request body', async () => {
      await request(app).post('/v1/auth/refresh-tokens').send().expect(httpStatus.BAD_REQUEST);
    });

    test('should return 401 error if refresh token is signed using an invalid secret', async () => {
      await insertUsers([userOne]);
      const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(
        dbUserOne.id,
        expires,
        TokenType.REFRESH,
        'invalidSecret'
      );
      await tokenService.saveToken(refreshToken, dbUserOne.id, expires, TokenType.REFRESH);

      await request(app)
        .post('/v1/auth/refresh-tokens')
        .send({ refreshToken })
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 error if refresh token is not found in the database', async () => {
      await insertUsers([userOne]);
      const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(dbUserOne.id, expires, TokenType.REFRESH);

      await request(app)
        .post('/v1/auth/refresh-tokens')
        .send({ refreshToken })
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 error if refresh token is blacklisted', async () => {
      await insertUsers([userOne]);
      const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(dbUserOne.id, expires, TokenType.REFRESH);
      await tokenService.saveToken(refreshToken, dbUserOne.id, expires, TokenType.REFRESH, true);

      await request(app)
        .post('/v1/auth/refresh-tokens')
        .send({ refreshToken })
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 error if refresh token is expired', async () => {
      await insertUsers([userOne]);
      const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
      const expires = moment().subtract(1, 'minutes');
      const refreshToken = tokenService.generateToken(dbUserOne.id, expires, TokenType.REFRESH);
      await tokenService.saveToken(refreshToken, dbUserOne.id, expires, TokenType.REFRESH);

      await request(app)
        .post('/v1/auth/refresh-tokens')
        .send({ refreshToken })
        .expect(httpStatus.UNAUTHORIZED);
    });

    // test('should return 401 error if user is not found', async () => {
    //   const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
    //   const refreshToken = tokenService.generateToken(dbUserOne.id, expires, TokenType.REFRESH);
    //   await tokenService.saveToken(refreshToken, dbUserOne.id, expires, TokenType.REFRESH);

    //   await request(app)
    //     .post('/v1/auth/refresh-tokens')
    //     .send({ refreshToken })
    //     .expect(httpStatus.UNAUTHORIZED);
    // });
  });

  describe('POST /v1/auth/forgot-password', () => {
    beforeEach(() => {
      jest.spyOn(emailService.transport, 'sendMail').mockClear();
    });

    test('should return 204 and send reset password email to the user', async () => {
      await insertUsers([userOne]);
      const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
      const sendResetPasswordEmailSpy = jest
        .spyOn(emailService, 'sendResetPasswordEmail')
        .mockImplementationOnce(() => new Promise((resolve) => resolve()));

      await request(app)
        .post('/v1/auth/forgot-password')
        .send({ email: userOne.email })
        .expect(httpStatus.NO_CONTENT);

      expect(sendResetPasswordEmailSpy).toHaveBeenCalledWith(userOne.email, expect.any(String));
      const resetPasswordToken = sendResetPasswordEmailSpy.mock.calls[0][1];
      const dbResetPasswordTokenData = await prisma.token.findFirst({
        where: {
          token: resetPasswordToken,
          userId: dbUserOne.id
        }
      });
      expect(dbResetPasswordTokenData).toBeDefined();
    });

    test('should return 400 if email is missing', async () => {
      await insertUsers([userOne]);

      await request(app).post('/v1/auth/forgot-password').send().expect(httpStatus.BAD_REQUEST);
    });

    test('should return 404 if email does not belong to any user', async () => {
      await request(app)
        .post('/v1/auth/forgot-password')
        .send({ email: userOne.email })
        .expect(httpStatus.NOT_FOUND);
    });
  });

  describe('POST /v1/auth/reset-password', () => {
    test('should return 204 and reset the password', async () => {
      await insertUsers([userOne]);
      const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
      const expires = moment().add(config.jwt.resetPasswordExpirationMinutes, 'minutes');
      const resetPasswordToken = tokenService.generateToken(
        dbUserOne.id,
        expires,
        TokenType.RESET_PASSWORD
      );
      await tokenService.saveToken(
        resetPasswordToken,
        dbUserOne.id,
        expires,
        TokenType.RESET_PASSWORD
      );

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password2' })
        .expect(httpStatus.NO_CONTENT);

      const dbUser = (await prisma.user.findUnique({ where: { id: dbUserOne.id } })) as User;
      const isPasswordMatch = await bcrypt.compare('password2', dbUser.password);
      expect(isPasswordMatch).toBe(true);

      const dbResetPasswordTokenCount = await prisma.token.count({
        where: {
          userId: dbUserOne.id,
          type: TokenType.RESET_PASSWORD
        }
      });
      expect(dbResetPasswordTokenCount).toBe(0);
    });

    test('should return 400 if reset password token is missing', async () => {
      await insertUsers([userOne]);

      await request(app)
        .post('/v1/auth/reset-password')
        .send({ password: 'password2' })
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 401 if reset password token is blacklisted', async () => {
      await insertUsers([userOne]);
      const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
      const expires = moment().add(config.jwt.resetPasswordExpirationMinutes, 'minutes');
      const resetPasswordToken = tokenService.generateToken(
        dbUserOne.id,
        expires,
        TokenType.RESET_PASSWORD
      );
      await tokenService.saveToken(
        resetPasswordToken,
        dbUserOne.id,
        expires,
        TokenType.RESET_PASSWORD,
        true
      );

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password2' })
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 if reset password token is expired', async () => {
      await insertUsers([userOne]);
      const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
      const expires = moment().subtract(1, 'minutes');
      const resetPasswordToken = tokenService.generateToken(
        dbUserOne.id,
        expires,
        TokenType.RESET_PASSWORD
      );
      await tokenService.saveToken(
        resetPasswordToken,
        dbUserOne.id,
        expires,
        TokenType.RESET_PASSWORD
      );

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password2' })
        .expect(httpStatus.UNAUTHORIZED);
    });

    // test('should return 401 if user is not found', async () => {
    //   const expires = moment().add(config.jwt.resetPasswordExpirationMinutes, 'minutes');
    //   const resetPasswordToken = tokenService.generateToken(
    //     dbUserOne.id,
    //     expires,
    //     TokenType.RESET_PASSWORD
    //   );
    //   await tokenService.saveToken(
    //     resetPasswordToken,
    //     dbUserOne.id,
    //     expires,
    //     TokenType.RESET_PASSWORD
    //   );

    //   await request(app)
    //     .post('/v1/auth/reset-password')
    //     .query({ token: resetPasswordToken })
    //     .send({ password: 'password2' })
    //     .expect(httpStatus.UNAUTHORIZED);
    // });

    test('should return 400 if password is missing or invalid', async () => {
      await insertUsers([userOne]);
      const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
      const expires = moment().add(config.jwt.resetPasswordExpirationMinutes, 'minutes');
      const resetPasswordToken = tokenService.generateToken(
        dbUserOne.id,
        expires,
        TokenType.RESET_PASSWORD
      );
      await tokenService.saveToken(
        resetPasswordToken,
        dbUserOne.id,
        expires,
        TokenType.RESET_PASSWORD
      );

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .expect(httpStatus.BAD_REQUEST);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'short1' })
        .expect(httpStatus.BAD_REQUEST);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password' })
        .expect(httpStatus.BAD_REQUEST);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: '11111111' })
        .expect(httpStatus.BAD_REQUEST);
    });
  });

  describe('POST /v1/auth/send-verification-email', () => {
    beforeEach(() => {
      jest.spyOn(emailService.transport, 'sendMail').mockClear();
    });

    test('should return 204 and send verification email to the user', async () => {
      await insertUsers([userOne]);
      const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
      const sendVerificationEmailSpy = jest
        .spyOn(emailService, 'sendVerificationEmail')
        .mockImplementationOnce(() => new Promise((resolve) => resolve()));
      const userOneAccessToken = tokenService.generateToken(
        dbUserOne.id,
        moment().add(config.jwt.accessExpirationMinutes, 'minutes'),
        TokenType.ACCESS
      );

      await request(app)
        .post('/v1/auth/send-verification-email')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .expect(httpStatus.NO_CONTENT);

      expect(sendVerificationEmailSpy).toHaveBeenCalledWith(userOne.email, expect.any(String));
      const verifyEmailToken = sendVerificationEmailSpy.mock.calls[0][1];
      const dbVerifyEmailToken = await prisma.token.findFirst({
        where: {
          token: verifyEmailToken,
          userId: dbUserOne.id
        }
      });

      expect(dbVerifyEmailToken).toBeDefined();
    });

    test('should return 401 error if access token is missing', async () => {
      await insertUsers([userOne]);

      await request(app)
        .post('/v1/auth/send-verification-email')
        .send()
        .expect(httpStatus.UNAUTHORIZED);
    });
  });

  describe('POST /v1/auth/verify-email', () => {
    test('should return 204 and verify the email', async () => {
      await insertUsers([userOne]);
      const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
      const expires = moment().add(config.jwt.verifyEmailExpirationMinutes, 'minutes');
      const verifyEmailToken = tokenService.generateToken(
        dbUserOne.id,
        expires,
        TokenType.VERIFY_EMAIL
      );
      await tokenService.saveToken(verifyEmailToken, dbUserOne.id, expires, TokenType.VERIFY_EMAIL);

      await request(app)
        .post('/v1/auth/verify-email')
        .query({ token: verifyEmailToken })
        .send()
        .expect(httpStatus.NO_CONTENT);

      const dbUser = (await prisma.user.findUnique({ where: { id: dbUserOne.id } })) as User;

      expect(dbUser.isEmailVerified).toBe(true);

      const dbVerifyEmailToken = await prisma.token.count({
        where: {
          userId: dbUserOne.id,
          type: TokenType.VERIFY_EMAIL
        }
      });
      expect(dbVerifyEmailToken).toBe(0);
    });

    test('should return 400 if verify email token is missing', async () => {
      await insertUsers([userOne]);

      await request(app).post('/v1/auth/verify-email').send().expect(httpStatus.BAD_REQUEST);
    });

    test('should return 401 if verify email token is blacklisted', async () => {
      await insertUsers([userOne]);
      const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
      const expires = moment().add(config.jwt.verifyEmailExpirationMinutes, 'minutes');
      const verifyEmailToken = tokenService.generateToken(
        dbUserOne.id,
        expires,
        TokenType.VERIFY_EMAIL
      );
      await tokenService.saveToken(
        verifyEmailToken,
        dbUserOne.id,
        expires,
        TokenType.VERIFY_EMAIL,
        true
      );

      await request(app)
        .post('/v1/auth/verify-email')
        .query({ token: verifyEmailToken })
        .send()
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 if verify email token is expired', async () => {
      await insertUsers([userOne]);
      const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
      const expires = moment().subtract(1, 'minutes');
      const verifyEmailToken = tokenService.generateToken(
        dbUserOne.id,
        expires,
        TokenType.VERIFY_EMAIL
      );
      await tokenService.saveToken(verifyEmailToken, dbUserOne.id, expires, TokenType.VERIFY_EMAIL);

      await request(app)
        .post('/v1/auth/verify-email')
        .query({ token: verifyEmailToken })
        .send()
        .expect(httpStatus.UNAUTHORIZED);
    });

    // test('should return 401 if user is not found', async () => {
    //   const expires = moment().add(config.jwt.verifyEmailExpirationMinutes, 'minutes');
    //   const verifyEmailToken = tokenService.generateToken(
    //     dbUserOne.id,
    //     expires,
    //     TokenType.VERIFY_EMAIL
    //   );
    //   await tokenService.saveToken(verifyEmailToken, dbUserOne.id, expires, TokenType.VERIFY_EMAIL);

    //   await request(app)
    //     .post('/v1/auth/verify-email')
    //     .query({ token: verifyEmailToken })
    //     .send()
    //     .expect(httpStatus.UNAUTHORIZED);
    // });
  });
});

describe('Auth middleware', () => {
  test('should call next with no errors if access token is valid', async () => {
    await insertUsers([userOne]);
    const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
    const userOneAccessToken = tokenService.generateToken(
      dbUserOne.id,
      moment().add(config.jwt.accessExpirationMinutes, 'minutes'),
      TokenType.ACCESS
    );
    const req = httpMocks.createRequest({
      headers: { Authorization: `Bearer ${userOneAccessToken}` }
    });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith();
    expect((req.user as User).id).toEqual(dbUserOne.id);
  });

  test('should call next with unauthorized error if access token is not found in header', async () => {
    await insertUsers([userOne]);
    const req = httpMocks.createRequest();
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: httpStatus.UNAUTHORIZED,
        message: 'Please authenticate'
      })
    );
  });

  test('should call next with unauthorized error if access token is not a valid jwt token', async () => {
    await insertUsers([userOne]);
    const req = httpMocks.createRequest({ headers: { Authorization: 'Bearer randomToken' } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: httpStatus.UNAUTHORIZED,
        message: 'Please authenticate'
      })
    );
  });

  test('should call next with unauthorized error if the token is not an access token', async () => {
    await insertUsers([userOne]);
    const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
    const expires = moment().add(config.jwt.accessExpirationMinutes, 'minutes');
    const refreshToken = tokenService.generateToken(dbUserOne.id, expires, TokenType.REFRESH);
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${refreshToken}` } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: httpStatus.UNAUTHORIZED,
        message: 'Please authenticate'
      })
    );
  });

  test('should call next with unauthorized error if access token is generated with an invalid secret', async () => {
    await insertUsers([userOne]);
    const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
    const expires = moment().add(config.jwt.accessExpirationMinutes, 'minutes');
    const accessToken = tokenService.generateToken(
      dbUserOne.id,
      expires,
      TokenType.ACCESS,
      'invalidSecret'
    );
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${accessToken}` } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: httpStatus.UNAUTHORIZED,
        message: 'Please authenticate'
      })
    );
  });

  test('should call next with unauthorized error if access token is expired', async () => {
    await insertUsers([userOne]);
    const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
    const expires = moment().subtract(1, 'minutes');
    const accessToken = tokenService.generateToken(dbUserOne.id, expires, TokenType.ACCESS);
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${accessToken}` } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: httpStatus.UNAUTHORIZED,
        message: 'Please authenticate'
      })
    );
  });

  test('should call next with unauthorized error if user is not found', async () => {
    const userOneAccessToken = tokenService.generateToken(
      2000,
      moment().add(config.jwt.accessExpirationMinutes, 'minutes'),
      TokenType.ACCESS
    );
    const req = httpMocks.createRequest({
      headers: { Authorization: `Bearer ${userOneAccessToken}` }
    });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: httpStatus.UNAUTHORIZED,
        message: 'Please authenticate'
      })
    );
  });

  test('should call next with forbidden error if user does not have required rights and userId is not in params', async () => {
    await insertUsers([userOne]);
    const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
    const userOneAccessToken = tokenService.generateToken(
      dbUserOne.id,
      moment().add(config.jwt.accessExpirationMinutes, 'minutes'),
      TokenType.ACCESS
    );
    const req = httpMocks.createRequest({
      headers: { Authorization: `Bearer ${userOneAccessToken}` }
    });
    const next = jest.fn();

    await auth('anyRight')(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: httpStatus.FORBIDDEN, message: 'Forbidden' })
    );
  });

  test('should call next with no errors if user does not have required rights but userId is in params', async () => {
    await insertUsers([userOne]);
    const dbUserOne = (await prisma.user.findUnique({ where: { email: userOne.email } })) as User;
    const userOneAccessToken = tokenService.generateToken(
      dbUserOne.id,
      moment().add(config.jwt.accessExpirationMinutes, 'minutes'),
      TokenType.ACCESS
    );
    const req = httpMocks.createRequest({
      headers: { Authorization: `Bearer ${userOneAccessToken}` },
      params: { userId: dbUserOne.id }
    });
    const next = jest.fn();

    await auth('anyRight')(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith();
  });

  test('should call next with no errors if user has required rights', async () => {
    await insertUsers([admin]);
    const dbAdmin = (await prisma.user.findUnique({ where: { email: admin.email } })) as User;
    const adminAccessToken = tokenService.generateToken(
      dbAdmin.id,
      moment().add(config.jwt.accessExpirationMinutes, 'minutes'),
      TokenType.ACCESS
    );
    const req = httpMocks.createRequest({
      headers: { Authorization: `Bearer ${adminAccessToken}` },
      params: { userId: dbAdmin.id }
    });
    const next = jest.fn();

    await auth(...(roleRights.get(Role.ADMIN) as string[]))(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith();
  });
});
