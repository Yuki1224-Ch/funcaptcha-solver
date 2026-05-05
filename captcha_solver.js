/**
 * Funcaptcha Solver Client
 * =========================
 * Communicates with the local funcaptcha-solver API to solve
 * Arkose Labs (Funcaptcha) challenges for Roblox login.
 */

import axios from 'axios';

// Configuration - replace with your actual config values
const CONFIG = {
    CAPTCHA_SOLVER_URL: process.env.CAPTCHA_SOLVER_URL || 'http://localhost:8003',
    CHROME_VERSION: process.env.CHROME_VERSION || '120.0.6099.109'
};

class CaptchaSolver {
    /**
     * Client for the funcaptcha-solver API.
     * @param {string} solverUrl - The URL of the captcha solver API
     */
    constructor(solverUrl = null) {
        this.solverUrl = solverUrl || CONFIG.CAPTCHA_SOLVER_URL;
        this.session = axios.create({
            timeout: 30000
        });
    }

    /**
     * Solve a Roblox login funcaptcha challenge.
     * @param {string|null} blob - The dxBlob data from the Roblox login challenge response
     * @param {string|null} proxy - Optional proxy string (e.g., "http://user:pass@host:port")
     * @returns {Promise<Object>} Object with 'success', 'token', 'error' keys
     */
    async solveRobloxLogin(blob = null, proxy = null) {
        const taskPayload = {
            preset: 'roblox_login',
            chrome_version: CONFIG.CHROME_VERSION
        };

        if (blob) {
            taskPayload.blob = blob;
        }

        if (proxy) {
            taskPayload.proxy = proxy;
        }

        try {
            // Create the captcha solving task
            const createResp = await this.session.post(
                `${this.solverUrl}/funcaptcha/createTask`,
                taskPayload
            );
            const createData = createResp.data;

            if (!createData.success) {
                return {
                    success: false,
                    token: null,
                    error: `Failed to create task: ${createData.err || 'unknown'}`
                };
            }

            const taskId = createData.task_id;

            // Poll for the result
            const maxWait = 120; // 2 minutes max
            const startTime = Date.now();

            while (Date.now() - startTime < maxWait * 1000) {
                const getResp = await this.session.post(
                    `${this.solverUrl}/funcaptcha/getTask`,
                    { task_id: taskId }
                );
                const result = getResp.data;

                if (result.status === 'completed') {
                    const captchaData = result.captcha || {};
                    if (captchaData.success) {
                        return {
                            success: true,
                            token: captchaData.token,
                            error: null,
                            solveTime: captchaData.procces_time
                        };
                    } else {
                        return {
                            success: false,
                            token: null,
                            error: `Captcha solve failed: ${captchaData.err || 'unknown'}`
                        };
                    }
                }

                // Still processing, wait and retry
                await new Promise(resolve => setTimeout(resolve, 2000));
            }

            return {
                success: false,
                token: null,
                error: 'Captcha solve timed out'
            };

        } catch (error) {
            if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
                return {
                    success: false,
                    token: null,
                    error: 'Cannot connect to captcha solver. Is it running on port 8003?'
                };
            }
            return {
                success: false,
                token: null,
                error: `Captcha solver error: ${error.message}`
            };
        }
    }

    /**
     * Check if the funcaptcha-solver API is reachable.
     * @returns {Promise<boolean>} True if the solver is running
     */
    async isSolverRunning() {
        try {
            await this.session.get(`${this.solverUrl}/`, { timeout: 5000 });
            return true;
        } catch (error) {
            return false;
        }
    }
}

export default CaptchaSolver;
