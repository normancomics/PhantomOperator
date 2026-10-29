/**
 * BrokerAgent.js
 *
 * Automated Data Broker Opt-Out & Statutory Takedown Engine (CCPA § 1798.105,
 * GDPR Art. 17, Virginia CDPA, California Delete Act SB 362).
 *
 * Maps 24+ major people-search and data-broker domains to their verified
 * opt-out portal URLs, privacy compliance email endpoints, SLA timelines, and
 * generates a legally formatted statutory erasure demand + tracking reference.
 */

'use strict';

const crypto = require('crypto');

const CALLER_ID_PROVIDERS = [
  { id: 'truecaller', name: 'Truecaller', removalUrl: 'https://www.truecaller.com/unlisting', notes: 'Deactivate the Truecaller account first. Spam-labelled numbers may not be eligible for unlisting.', expectedDays: 1 },
  { id: 'hiya', name: 'Hiya', removalUrl: 'https://apphelp.hiya.com/en/articles/38-your-data-and-privacy', notes: 'Use Hiya data-management tools; proof of ownership may be required.', expectedDays: 30 },
  { id: 'robokiller', name: 'RoboKiller', removalUrl: 'https://support.robokiller.com/hc/en-us/articles/37870138815892-My-number-is-incorrectly-marked-as-spam-What-should-I-do', notes: 'Use the Global Blacklist removal request for incorrectly flagged legitimate numbers.', expectedDays: null },
  { id: 'whitepages', name: 'Whitepages', removalUrl: 'https://www.whitepages.com/suppression-requests', notes: 'Submit the listing URL through the suppression tool. Removal affects Whitepages-controlled records only.', expectedDays: 3 },
];

const BROKER_PATTERNS = [
  { domain: 'spokeo.com',                name: 'Spokeo',                optOutUrl: 'https://www.spokeo.com/optout',                         privacyEmail: 'privacy@spokeo.com',                slaDays: 3 },
  { domain: 'whitepages.com',            name: 'Whitepages',            optOutUrl: 'https://www.whitepages.com/suppression-requests',       privacyEmail: 'privacy@whitepages.com',            slaDays: 5 },
  { domain: 'intelius.com',              name: 'Intelius',              optOutUrl: 'https://suppression.peopleconnect.us/login',            privacyEmail: 'privacy@peopleconnect.us',          slaDays: 3 },
  { domain: 'beenverified.com',          name: 'BeenVerified',          optOutUrl: 'https://www.beenverified.com/app/optout/search',        privacyEmail: 'privacy@beenverified.com',          slaDays: 3 },
  { domain: 'peoplefinder.com',          name: 'PeopleFinder',          optOutUrl: 'https://suppression.peopleconnect.us/login',            privacyEmail: 'privacy@peopleconnect.us',          slaDays: 3 },
  { domain: 'radaris.com',               name: 'Radaris',               optOutUrl: 'https://radaris.com/control/privacy',                   privacyEmail: 'privacy@radaris.com',               slaDays: 7 },
  { domain: 'mylife.com',                name: 'MyLife',                optOutUrl: 'https://www.mylife.com/ccpa/index.pubview',             privacyEmail: 'privacy@mylife.com',                slaDays: 10 },
  { domain: 'instantcheckmate.com',      name: 'InstantCheckmate',      optOutUrl: 'https://suppression.peopleconnect.us/login',            privacyEmail: 'privacy@peopleconnect.us',          slaDays: 3 },
  { domain: 'truthfinder.com',           name: 'TruthFinder',           optOutUrl: 'https://suppression.peopleconnect.us/login',            privacyEmail: 'privacy@peopleconnect.us',          slaDays: 3 },
  { domain: 'zabasearch.com',            name: 'ZabaSearch',            optOutUrl: 'https://www.zabasearch.com/block_records/',             privacyEmail: 'privacy@zabasearch.com',            slaDays: 7 },
  { domain: 'pipl.com',                  name: 'Pipl',                  optOutUrl: 'https://pipl.com/personal-information-removal-request', privacyEmail: 'privacy@pipl.com',                  slaDays: 14 },
  { domain: 'fastpeoplesearch.com',      name: 'FastPeopleSearch',      optOutUrl: 'https://www.fastpeoplesearch.com/removal',              privacyEmail: 'privacy@fastpeoplesearch.com',      slaDays: 3 },
  { domain: 'thatsthem.com',             name: 'ThatsThem',             optOutUrl: 'https://thatsthem.com/optout',                          privacyEmail: 'privacy@thatsthem.com',             slaDays: 5 },
  { domain: 'usersearch.org',            name: 'UserSearch',            optOutUrl: 'https://usersearch.org/optout.php',                     privacyEmail: 'support@usersearch.org',            slaDays: 7 },
  { domain: 'truepeoplesearch.com',      name: 'TruePeopleSearch',      optOutUrl: 'https://www.truepeoplesearch.com/removal',              privacyEmail: 'support@truepeoplesearch.com',      slaDays: 3 },
  { domain: 'familytreenow.com',         name: 'FamilyTreeNow',         optOutUrl: 'https://www.familytreenow.com/optout',                  privacyEmail: 'privacy@familytreenow.com',         slaDays: 3 },
  { domain: 'cyberbackgroundchecks.com', name: 'CyberBackgroundChecks', optOutUrl: 'https://www.cyberbackgroundchecks.com/removal',         privacyEmail: 'privacy@cyberbackgroundchecks.com', slaDays: 5 },
  { domain: 'usphonebook.com',           name: 'USPhoneBook',           optOutUrl: 'https://www.usphonebook.com/opt-out',                   privacyEmail: 'privacy@usphonebook.com',           slaDays: 3 },
  { domain: 'clustrmaps.com',            name: 'ClustrMaps',            optOutUrl: 'https://clustrmaps.com/bl/opt-out',                     privacyEmail: 'MetricMaps@gmail.com',              slaDays: 7 },
  { domain: 'peekyou.com',               name: 'PeekYou',               optOutUrl: 'https://www.peekyou.com/about/contact/optout',          privacyEmail: 'privacy@peekyou.com',               slaDays: 7 },
  { domain: 'nuwber.com',                name: 'Nuwber',                optOutUrl: 'https://nuwber.com/removal/link',                       privacyEmail: 'support@nuwber.com',                slaDays: 3 },
  { domain: 'rocketreach.co',            name: 'RocketReach',           optOutUrl: 'https://rocketreach.co/dsar',                           privacyEmail: 'privacy@rocketreach.co',            slaDays: 10 },
  { domain: 'zoominfo.com',              name: 'ZoomInfo',              optOutUrl: 'https://www.zoominfo.com/about-zoominfo/privacy-manage-profile', privacyEmail: 'privacy@zoominfo.com',     slaDays: 10 },
  { domain: 'apollo.io',                 name: 'Apollo.io',             optOutUrl: 'https://www.apollo.io/privacy-policy/remove',           privacyEmail: 'privacy@apollo.io',                 slaDays: 10 },
];

function buildStatutoryNotice({ brokerName, link, fullName, trackingId }) {
  const subject = fullName || 'Authorized Data Subject';
  const dateStr = new Date().toISOString().slice(0, 10);
  return (
    `STATUTORY NOTICE OF DATA ERASURE & OPT-OUT DEMAND (Ref: ${trackingId})\n` +
    `Date: ${dateStr}\n` +
    `To: Privacy & Statutory Compliance Officer — ${brokerName}\n` +
    `Data Subject: ${subject}\n` +
    `Target Record URI: ${link}\n\n` +
    `Pursuant to the California Consumer Privacy Act / CPRA (Cal. Civ. Code § 1798.105 & § 1798.120), ` +
    `the California Delete Act (SB 362), GDPR Article 17 (Right to Erasure), and applicable state privacy ` +
    `statutes (Virginia CDPA, Colorado CPA, Texas TDPSA), I hereby demand the immediate deletion and ` +
    `permanent suppression of all personal information, profile records, and derived identifiers ` +
    `associated with ${subject} at ${link} and across all affiliated data broker properties.`
  );
}

class BrokerAgent {
  constructor(config = {}) {
    this.config = config;
  }

  async scheduleOptOuts(exposures, user) {
    const jobs = exposures.map((exp, idx) => ({
      broker: exp.source,
      job_id: `job-${idx + 1}`,
      status: 'PENDING',
      notes: `Demo opt-out job for ${user.email || user.name || 'user'} at ${exp.source}`,
    }));

    return { jobs };
  }

  /**
   * Submit / prepare a data-removal workflow for a single threat URL.
   *
   * @param {{ link: string, fullName?: string }} params
   * @returns {Promise<{
   *   broker: string,
   *   status: 'submitted'|'unsupported'|'failed',
   *   detail: string,
   *   trackingId?: string,
   *   optOutUrl?: string,
   *   privacyEmail?: string,
   *   estimatedCompletionDays?: number,
   *   statutoryNotice?: string
   * }>}
   */
  static async removeThreat({ link, fullName }) {
    if (!link) {
      return { broker: 'unknown', status: 'failed', detail: 'No URL provided' };
    }

    let hostname = '';
    try {
      hostname = new URL(link).hostname.replace(/^www\./, '');
    } catch {
      return { broker: 'unknown', status: 'failed', detail: `Invalid URL: ${link}` };
    }

    const matched = BROKER_PATTERNS.find(
      (b) => hostname === b.domain || hostname.endsWith(`.${b.domain}`)
    );
    const brokerName = matched ? matched.name : hostname;
    const trackingId = 'PO-' + crypto.createHash('sha256').update(`${link}:${fullName || ''}`).digest('hex').slice(0, 12).toUpperCase();

    try {
      console.log(
        `BrokerAgent.removeThreat: queuing removal for ${brokerName} | url=${link}` +
        (fullName ? ` | name=${fullName}` : '')
      );

      if (!matched) {
        return {
          broker: brokerName,
          status: 'unsupported',
          detail: `No automated opt-out portal registered for ${hostname}. Use the generated statutory CCPA/GDPR notice for manual submission.`,
          trackingId,
          statutoryNotice: buildStatutoryNotice({ brokerName, link, fullName, trackingId }),
        };
      }

      return {
        broker: brokerName,
        status: 'prepared',
        detail: `Removal guidance prepared for ${brokerName} (${link}). Submit directly through: ${matched.optOutUrl}`,
        trackingId,
        optOutUrl: matched.optOutUrl,
        privacyEmail: matched.privacyEmail,
        estimatedCompletionDays: matched.slaDays,
        statutoryNotice: buildStatutoryNotice({ brokerName, link, fullName, trackingId }),
      };
    } catch (err) {
      return { broker: brokerName, status: 'failed', detail: err.message };
    }
  }
}

/**
 * Produce official removal/dispute steps for caller-ID and spam-label services.
 * This function never submits on a user's behalf; the authorization flag records
 * that the caller is requesting guidance for their own number or an authorized client.
 */
BrokerAgent.prepareCallerIdRemoval = async ({ phoneNumber, provider, authorized }) => {
  if (!authorized) throw new Error('Explicit authorization is required for caller-ID removal guidance.');
  const normalized = String(phoneNumber || '').replace(/[\s().-]/g, '');
  if (!/^\+?[1-9]\d{6,14}$/.test(normalized)) throw new Error('phoneNumber must be a valid international-format phone number.');
  const selected = provider ? CALLER_ID_PROVIDERS.filter((p) => p.id === provider) : CALLER_ID_PROVIDERS;
  if (provider && selected.length === 0) throw new Error('Unsupported provider. Use truecaller, hiya, robokiller, or whitepages.');
  return {
    status: 'prepared',
    phoneNumber: normalized,
    authorizationRequired: true,
    disclaimer: 'PhantomOperator provides official removal/dispute steps only. The user must submit and complete each provider process; caches and third-party datasets may remain.',
    providers: selected.map((p) => ({ ...p, request: `Request removal or dispute for the authorized number ${normalized}.` })),
  };
};

module.exports = BrokerAgent;
