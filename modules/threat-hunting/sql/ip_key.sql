CASE
  WHEN regexp_like(IP_IN, '^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])[.]){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$')
    THEN '00000000000000000000ffff' || substr('0123456789abcdef', CAST(floor(TRY_CAST(split_part(IP_IN, '.', 1) AS integer) / 16.0) AS integer) + 1, 1) || substr('0123456789abcdef', TRY_CAST(split_part(IP_IN, '.', 1) AS integer) % 16 + 1, 1) || substr('0123456789abcdef', CAST(floor(TRY_CAST(split_part(IP_IN, '.', 2) AS integer) / 16.0) AS integer) + 1, 1) || substr('0123456789abcdef', TRY_CAST(split_part(IP_IN, '.', 2) AS integer) % 16 + 1, 1) || substr('0123456789abcdef', CAST(floor(TRY_CAST(split_part(IP_IN, '.', 3) AS integer) / 16.0) AS integer) + 1, 1) || substr('0123456789abcdef', TRY_CAST(split_part(IP_IN, '.', 3) AS integer) % 16 + 1, 1) || substr('0123456789abcdef', CAST(floor(TRY_CAST(split_part(IP_IN, '.', 4) AS integer) / 16.0) AS integer) + 1, 1) || substr('0123456789abcdef', TRY_CAST(split_part(IP_IN, '.', 4) AS integer) % 16 + 1, 1)
  WHEN regexp_like(lower(IP_IN), '^[0-9a-f:]+$')
   AND NOT regexp_like(lower(IP_IN), '[0-9a-f]{5}|:::')
   AND length(lower(IP_IN)) - length(replace(lower(IP_IN), '::', '')) <= 2
   AND (strpos(lower(IP_IN), '::') = 0 OR cardinality(regexp_extract_all(lower(IP_IN), '[0-9a-f]+')) <= 7)
   AND cardinality(split(CASE WHEN strpos(lower(IP_IN), '::') > 0 THEN regexp_replace(replace(lower(IP_IN), '::', ':' || substr('0:0:0:0:0:0:0:0:', 1, 2 * greatest(0, 8 - cardinality(regexp_extract_all(lower(IP_IN), '[0-9a-f]+'))))), '^:|:$', '') ELSE lower(IP_IN) END, ':')) = 8
    THEN array_join(transform(split(CASE WHEN strpos(lower(IP_IN), '::') > 0 THEN regexp_replace(replace(lower(IP_IN), '::', ':' || substr('0:0:0:0:0:0:0:0:', 1, 2 * greatest(0, 8 - cardinality(regexp_extract_all(lower(IP_IN), '[0-9a-f]+'))))), '^:|:$', '') ELSE lower(IP_IN) END, ':'), grp -> lpad(grp, 4, '0')), '')
END
