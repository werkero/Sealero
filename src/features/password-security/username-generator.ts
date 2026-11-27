/**
 * Word-based username generator.
 *
 * Usernames are built from common English words (adjective + noun, with an
 * optional two-digit number), so they are readable and easy to type. Only
 * ASCII letters, digits and the separators `-` / `_` are used, which every
 * username field accepts. Randomness comes from WebCrypto, like the password
 * generator; no username is ever sent anywhere.
 */

export type UsernameSeparator = '-' | '_' | ''

export interface UsernameGeneratorOptions {
  includeNumber: boolean
  separator: UsernameSeparator
  capitalize: boolean
}

export const DEFAULT_USERNAME_OPTIONS: UsernameGeneratorOptions = {
  includeNumber: true,
  separator: '-',
  capitalize: false,
}

const ADJECTIVES = [
  'swift', 'brave', 'calm', 'bright', 'clever', 'silent', 'happy', 'lucky',
  'rapid', 'gentle', 'bold', 'keen', 'warm', 'cool', 'wild', 'free',
  'noble', 'grand', 'quick', 'smart', 'kind', 'proud', 'vivid', 'crisp',
  'lucid', 'merry', 'nimble', 'placid', 'radiant', 'serene', 'sturdy',
  'eager', 'frosty', 'golden', 'hidden', 'jolly', 'mellow', 'quiet',
  'steady', 'sunny', 'tender', 'valiant', 'witty', 'zealous', 'amber',
  'cobalt', 'crimson', 'emerald', 'ivory', 'scarlet',
]

const NOUNS = [
  'fox', 'wolf', 'bear', 'eagle', 'falcon', 'river', 'mountain', 'ocean',
  'forest', 'meadow', 'harbor', 'summit', 'valley', 'comet', 'meteor',
  'nebula', 'pulsar', 'willow', 'cedar', 'maple', 'birch', 'heron',
  'otter', 'badger', 'lynx', 'raven', 'hawk', 'dune', 'fjord', 'glacier',
  'lagoon', 'prairie', 'canyon', 'cascade', 'ember', 'frost', 'grove',
  'haven', 'island', 'juniper', 'kepler', 'lantern', 'marble', 'nomad',
  'onyx', 'pebble', 'quartz', 'ridge', 'sable',
]

function secureRandomIndex(max: number): number {
  const limit = Math.floor(0xffffffff / max) * max
  const value = new Uint32Array(1)
  for (;;) {
    globalThis.crypto.getRandomValues(value)
    if (value[0] < limit) return value[0] % max
  }
}

function capitalizeWord(word: string): string {
  return word[0].toUpperCase() + word.slice(1)
}

export function generateUsername(options: UsernameGeneratorOptions): string {
  const adjective = ADJECTIVES[secureRandomIndex(ADJECTIVES.length)]
  const noun = NOUNS[secureRandomIndex(NOUNS.length)]
  const words = options.capitalize ? [capitalizeWord(adjective), capitalizeWord(noun)] : [adjective, noun]
  const parts = [...words]
  if (options.includeNumber) parts.push(String(10 + secureRandomIndex(90)))
  return parts.join(options.separator)
}
