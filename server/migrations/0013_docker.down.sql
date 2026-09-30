BEGIN;

DROP TABLE swarm_services;
DROP TABLE swarm_clusters;
DROP TABLE host_docker;
DROP TABLE host_containers;
DROP TABLE host_images;
DROP TABLE container_images;
DELETE FROM host_fact_state WHERE kind IN ('containers:docker', 'images:docker');

COMMIT;
