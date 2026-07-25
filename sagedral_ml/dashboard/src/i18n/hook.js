import { useCallback, useMemo } from 'react';
import TET from './index';

export function useTranslation() {
  const t = useCallback((key, params = {}) => {
    const template = TET[key] || key;
    return Object.keys(params).reduce(
      (str, paramKey) => str.replaceAll(`{${paramKey}}`, params[paramKey]),
      template
    );
  }, []);

  const T = useMemo(() => TET, []);

  return { t, T };
}

export default useTranslation;
