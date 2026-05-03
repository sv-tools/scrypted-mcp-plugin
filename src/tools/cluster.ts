import { z } from 'zod';
import { getComponent } from '../scrypted';

interface ClusterForkComponent {
    getClusterWorkers(): Promise<
        Record<
            string,
            {
                id: string;
                name: string;
                labels: unknown;
                forks: unknown[];
                mode: string;
                address: string;
            }
        >
    >;
}

export const listClusterWorkersInput = z.object({});

export async function listClusterWorkers() {
    const cluster = await getComponent<ClusterForkComponent>('cluster-fork');
    const workers = await cluster.getClusterWorkers();
    const list = Object.values(workers);
    return { count: list.length, workers: list };
}
