BEGIN;


ALTER TABLE public.device_certificates_history 
ADD COLUMN status TEXT default ''
COMMIT;