/**
 * Exclude keys from object
 * @param obj
 * @param keys
 * @returns
 */
const exclude = <Type, Key extends keyof Type>(obj: Type, keys: Key[]): Omit<Type, Key> => {
  for (let key of keys) {
    delete obj[key];
  }
  return obj;
};

export default exclude;
