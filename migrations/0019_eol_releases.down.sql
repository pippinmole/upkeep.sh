-- Removes the end-of-life releases 0019 listed. Nothing was imported for
-- them (never supported); their image packages go back to "release not
-- recognised", which is still not assessed.

BEGIN;

DELETE FROM distro_releases WHERE (distro, codename) IN (
    ('debian', 'jessie'), ('debian', 'stretch'), ('debian', 'buster'),
    ('ubuntu', 'trusty'), ('ubuntu', 'xenial'), ('ubuntu', 'bionic'), ('ubuntu', 'kinetic'),
    ('ubuntu', 'lunar'), ('ubuntu', 'mantic'), ('ubuntu', 'oracular'), ('ubuntu', 'plucky'),
    ('alpine', '3.14'), ('alpine', '3.15'), ('alpine', '3.16'), ('alpine', '3.17'), ('alpine', '3.18')
) AND NOT supported;

COMMIT;
