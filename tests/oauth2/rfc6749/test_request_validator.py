# -*- coding: utf-8 -*-
from oauthlib.oauth2 import RequestValidator

from tests.unittest import TestCase


class RequestValidatorTest(TestCase):

    async def test_method_contracts(self):
        v = RequestValidator()
        with self.assertRaises(NotImplementedError):
            await v.authenticate_client('r')
        with self.assertRaises(NotImplementedError):
            await v.authenticate_client_id('client_id', 'r')
        with self.assertRaises(NotImplementedError):
            await v.confirm_redirect_uri('client_id', 'code', 'redirect_uri', 'client', 'request')
        with self.assertRaises(NotImplementedError):
            await v.get_default_redirect_uri('client_id', 'request')
        with self.assertRaises(NotImplementedError):
            await v.get_default_scopes('client_id', 'request')
        with self.assertRaises(NotImplementedError):
            await v.get_original_scopes('refresh_token', 'request')
        self.assertFalse(await v.is_within_original_scope(
                ['scope'], 'refresh_token', 'request'))
        with self.assertRaises(NotImplementedError):
            await v.invalidate_authorization_code('client_id', 'code', 'request')
        with self.assertRaises(NotImplementedError):
            await v.save_authorization_code('client_id', 'code', 'request')
        with self.assertRaises(NotImplementedError):
            await v.save_bearer_token('token', 'request')
        with self.assertRaises(NotImplementedError):
            await v.validate_bearer_token('token', 'scopes', 'request')
        with self.assertRaises(NotImplementedError):
            await v.validate_client_id('client_id', 'request')
        with self.assertRaises(NotImplementedError):
            await v.validate_code('client_id', 'code', 'client', 'request')
        with self.assertRaises(NotImplementedError):
            await v.validate_grant_type('client_id', 'grant_type', 'client', 'request')
        with self.assertRaises(NotImplementedError):
            await v.validate_redirect_uri('client_id', 'redirect_uri', 'request')
        with self.assertRaises(NotImplementedError):
            await v.validate_refresh_token('refresh_token', 'client', 'request')
        with self.assertRaises(NotImplementedError):
            await v.validate_response_type('client_id', 'response_type', 'client', 'request')
        with self.assertRaises(NotImplementedError):
            await v.validate_scopes('client_id', 'scopes', 'client', 'request')
        with self.assertRaises(NotImplementedError):
            await v.validate_user('username', 'password', 'client', 'request')
        self.assertTrue(await v.client_authentication_required('r'))
        self.assertFalse(
            await v.is_origin_allowed('client_id', 'https://foo.bar', 'r')
        )
