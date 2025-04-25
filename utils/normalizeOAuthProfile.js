function normalizeOAuthProfile(provider, profile) {
    switch (provider) {
        case 'google':
            return {
                email: profile.emails?.[0]?.value || '',
                firstName: profile.name?.givenName || '',
                lastName: profile.name?.familyName || '',
                avatar: profile.photos?.[0]?.value || ''
            };

        case 'facebook':
            return {
                email: profile.emails?.[0]?.value || '',
                firstName: profile.name?.givenName || '',
                lastName: profile.name?.familyName || '',
                avatar: `https://graph.facebook.com/${profile.id}/picture?type=large`
            };

        case 'github':
            const displayName = profile.displayName || '';
            const [firstName, ...rest] = displayName.split(' ');
            const lastName = rest.join(' ') || '';
            return {
                email: profile.emails?.[0]?.value || '',
                firstName: firstName || '',
                lastName: lastName || '',
                avatar: profile.photos?.[0]?.value || ''
            };

        default:
            return {
                email: '',
                firstName: '',
                lastName: '',
                avatar: ''
            };
    }
}

module.exports = normalizeOAuthProfile;