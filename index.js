/**
 * Provides middleware for authentification & authorization via Github
 */

const cookieParser = require('cookie-parser');
const express = require('express');
const logger = require('@log4js-node/log4js-api').getLogger('auth');
const passport = require('passport');
const session = require('express-session');
const GitHubStrategy = require('passport-github').Strategy;

function redirect(res, location) {
	res.writeHead(302, {
		Location: location,
	});
	return res.end();
}

function initPassport(githubRedirectUrl, githubClientId, githubClientSecret) {
	passport.use(new GitHubStrategy({
		callbackURL: githubRedirectUrl,
		clientID: githubClientId,
		clientSecret: githubClientSecret,
	},
	(accessToken, refreshToken, profile, cb) => { // eslint-disable-line max-params
		logger.info(`Authenticated ${profile.username}`);
		cb(null, profile.username);
	}));
	passport.serializeUser((username, cb) => cb(null, username));
	passport.deserializeUser((username, cb) => cb(null, username));
}

// Route middleware to make sure a user is logged in
function createIsLoggedIn(whiteListedUsers) {
	return function isLoggedIn(req, res, next) {
		if (!req.isAuthenticated()) {
			// If they aren't redirect them to the home page
			logger.info('Unauthenticated request. Forwarded to login.');
			return redirect(res, '/auth/github');
		}

		// User is authenticated, check that they are authorized.
		if (!whiteListedUsers.includes(req.user)) {
			logger.warn(`User ${req.user} isn't authorized to use this application. White listed users: ${whiteListedUsers}`);
			return res.status(403);
		}

		// User is authorized to proceed and actually use the app.
		return next();
	};
}

const githubAuthRouter = express.Router();
githubAuthRouter.get('/auth/github', passport.authenticate('github'));
githubAuthRouter.get('/auth/github/callback',
	passport.authenticate('github', {failureRedirect: '/auth/github'}),
	(req, res) => {
		logger.info(`Successfully authenticated ${req.user}, redirect to home.`);
		// Wait until cookie is set
		setTimeout(() => redirect(res, '/'), 500);
	});

module.exports = ({githubRedirectUrl, githubClientId, githubClientSecret, githubSessionSecret, whiteListedUsers}) => {
	if (!whiteListedUsers || whiteListedUsers.length === 0) {
		throw new Error('Some users must be whitelisted');
	}

	initPassport(githubRedirectUrl, githubClientId, githubClientSecret);

	return {
		isLoggedIn: createIsLoggedIn(whiteListedUsers),
		middleware: [
			cookieParser(),
			session({secret: githubSessionSecret}),
			passport.initialize(),
			passport.session(),
			githubAuthRouter,
		],
	};
};
