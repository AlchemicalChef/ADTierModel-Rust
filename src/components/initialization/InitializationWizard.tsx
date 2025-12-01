import { useState, useEffect } from "react";
import {
  CheckCircleIcon,
  ExclamationTriangleIcon,
  XCircleIcon,
  FolderPlusIcon,
  UserGroupIcon,
  ShieldCheckIcon,
  DocumentDuplicateIcon,
  ArrowPathIcon,
} from "@heroicons/react/24/outline";
import {
  checkTierInitialization,
  initializeAdTierModel,
  getExpectedOuStructure,
  getExpectedGroups,
} from "../../services/tauri";
import type {
  InitializationOptions,
  InitializationResult,
  InitializationStatus,
} from "../../types/tier";

interface InitializationWizardProps {
  onComplete: () => void;
  onSkip: () => void;
}

type WizardStep = "check" | "configure" | "preview" | "execute" | "complete";

export function InitializationWizard({
  onComplete,
  onSkip,
}: InitializationWizardProps) {
  const [step, setStep] = useState<WizardStep>("check");
  const [status, setStatus] = useState<InitializationStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<InitializationResult | null>(null);
  const [showSkipWarning, setShowSkipWarning] = useState(false);

  // Options state
  const [options, setOptions] = useState<InitializationOptions>({
    createOuStructure: true,
    createGroups: true,
    setPermissions: false,
    createGpos: false,
    force: false,
  });

  // Preview data
  const [expectedOus, setExpectedOus] = useState<string[]>([]);
  const [expectedGroups, setExpectedGroups] = useState<string[]>([]);

  // Check initialization status on mount
  useEffect(() => {
    checkStatus();
  }, []);

  const checkStatus = async () => {
    setLoading(true);
    setError(null);
    try {
      const initStatus = await checkTierInitialization();
      setStatus(initStatus);

      if (initStatus.isInitialized) {
        // Already initialized, skip wizard
        onComplete();
      }
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to check initialization status"
      );
    } finally {
      setLoading(false);
    }
  };

  const loadPreview = async () => {
    setLoading(true);
    try {
      const [ous, groups] = await Promise.all([
        getExpectedOuStructure(),
        getExpectedGroups(),
      ]);
      setExpectedOus(ous);
      setExpectedGroups(groups);
      setStep("preview");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load preview");
    } finally {
      setLoading(false);
    }
  };

  const executeInitialization = async () => {
    setStep("execute");
    setLoading(true);
    setError(null);
    try {
      const initResult = await initializeAdTierModel(options);
      setResult(initResult);
      setStep("complete");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Initialization failed");
      setStep("preview"); // Go back to allow retry
    } finally {
      setLoading(false);
    }
  };

  const renderCheckStep = () => (
    <div className="space-y-6">
      <div className="text-center">
        <ShieldCheckIcon className="h-16 w-16 mx-auto text-blue-500" />
        <h2 className="mt-4 text-xl font-semibold text-gray-900 dark:text-white">
          AD Tier Model Setup
        </h2>
        <p className="mt-2 text-gray-600 dark:text-gray-400">
          Checking your Active Directory environment...
        </p>
      </div>

      {loading && (
        <div className="flex items-center justify-center py-8">
          <ArrowPathIcon className="h-8 w-8 animate-spin text-blue-500" />
        </div>
      )}

      {error && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
          <div className="flex items-center gap-2 text-red-800 dark:text-red-200">
            <XCircleIcon className="h-5 w-5" />
            <span>{error}</span>
          </div>
        </div>
      )}

      {status && !status.isInitialized && (
        <div className="space-y-4">
          <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg p-4">
            <div className="flex items-center gap-2 text-amber-800 dark:text-amber-200">
              <ExclamationTriangleIcon className="h-5 w-5" />
              <span className="font-medium">Tier Model Not Initialized</span>
            </div>
            <p className="mt-2 text-sm text-amber-700 dark:text-amber-300">
              The AD Tier Model structure has not been set up in your domain.
            </p>
          </div>

          {status.missingComponents.length > 0 && (
            <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4">
              <h4 className="font-medium text-gray-900 dark:text-white mb-2">
                Missing Components:
              </h4>
              <ul className="list-disc list-inside text-sm text-gray-600 dark:text-gray-400">
                {status.missingComponents.map((component, i) => (
                  <li key={i}>{component}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="flex justify-end gap-3">
            <button
              onClick={() => setShowSkipWarning(true)}
              className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
            >
              Skip for Now
            </button>
            <button
              onClick={() => setStep("configure")}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              Initialize Now
            </button>
          </div>
        </div>
      )}
    </div>
  );

  const renderConfigureStep = () => (
    <div className="space-y-6">
      <div className="text-center">
        <FolderPlusIcon className="h-16 w-16 mx-auto text-blue-500" />
        <h2 className="mt-4 text-xl font-semibold text-gray-900 dark:text-white">
          Configure Initialization
        </h2>
        <p className="mt-2 text-gray-600 dark:text-gray-400">
          Select which components to create
        </p>
      </div>

      <div className="space-y-4">
        <label className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
          <input
            type="checkbox"
            checked={options.createOuStructure}
            onChange={(e) =>
              setOptions({ ...options, createOuStructure: e.target.checked })
            }
            className="h-5 w-5 rounded text-blue-600"
          />
          <div className="flex items-center gap-2">
            <FolderPlusIcon className="h-5 w-5 text-blue-500" />
            <div>
              <div className="font-medium text-gray-900 dark:text-white">
                Create OU Structure
              </div>
              <div className="text-sm text-gray-500 dark:text-gray-400">
                Tier0, Tier1, Tier2 OUs with sub-OUs
              </div>
            </div>
          </div>
        </label>

        <label className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
          <input
            type="checkbox"
            checked={options.createGroups}
            onChange={(e) =>
              setOptions({ ...options, createGroups: e.target.checked })
            }
            className="h-5 w-5 rounded text-blue-600"
          />
          <div className="flex items-center gap-2">
            <UserGroupIcon className="h-5 w-5 text-green-500" />
            <div>
              <div className="font-medium text-gray-900 dark:text-white">
                Create Security Groups
              </div>
              <div className="text-sm text-gray-500 dark:text-gray-400">
                Admins, Operators, Readers, ServiceAccounts, JumpServers
              </div>
            </div>
          </div>
        </label>

        <label className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
          <input
            type="checkbox"
            checked={options.setPermissions}
            onChange={(e) =>
              setOptions({ ...options, setPermissions: e.target.checked })
            }
            className="h-5 w-5 rounded text-blue-600"
          />
          <div className="flex items-center gap-2">
            <ShieldCheckIcon className="h-5 w-5 text-amber-500" />
            <div>
              <div className="font-medium text-gray-900 dark:text-white">
                Set Permissions
              </div>
              <div className="text-sm text-gray-500 dark:text-gray-400">
                Delegate control to tier admin groups &amp; protect OUs
              </div>
            </div>
          </div>
        </label>

        <label className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
          <input
            type="checkbox"
            checked={options.createGpos}
            onChange={(e) =>
              setOptions({ ...options, createGpos: e.target.checked })
            }
            className="h-5 w-5 rounded text-blue-600"
          />
          <div className="flex items-center gap-2">
            <DocumentDuplicateIcon className="h-5 w-5 text-purple-500" />
            <div>
              <div className="font-medium text-gray-900 dark:text-white">
                Create GPOs
              </div>
              <div className="text-sm text-gray-500 dark:text-gray-400">
                Logon restrictions to enforce tier separation (requires RSAT)
              </div>
            </div>
          </div>
        </label>
      </div>

      <div className="flex justify-between">
        <button
          onClick={() => setStep("check")}
          className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
        >
          Back
        </button>
        <button
          onClick={loadPreview}
          disabled={!options.createOuStructure && !options.createGroups}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Preview Changes
        </button>
      </div>
    </div>
  );

  const renderPreviewStep = () => (
    <div className="space-y-6">
      <div className="text-center">
        <DocumentDuplicateIcon className="h-16 w-16 mx-auto text-blue-500" />
        <h2 className="mt-4 text-xl font-semibold text-gray-900 dark:text-white">
          Review Changes
        </h2>
        <p className="mt-2 text-gray-600 dark:text-gray-400">
          The following objects will be created in Active Directory
        </p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-8">
          <ArrowPathIcon className="h-8 w-8 animate-spin text-blue-500" />
        </div>
      ) : (
        <div className="space-y-4 max-h-80 overflow-auto">
          {options.createOuStructure && expectedOus.length > 0 && (
            <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4">
              <h4 className="flex items-center gap-2 font-medium text-gray-900 dark:text-white mb-2">
                <FolderPlusIcon className="h-5 w-5 text-blue-500" />
                Organizational Units ({expectedOus.length})
              </h4>
              <ul className="text-sm text-gray-600 dark:text-gray-400 space-y-1 font-mono">
                {expectedOus.map((ou, i) => (
                  <li key={i} className="truncate" title={ou}>
                    {ou}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {options.createGroups && expectedGroups.length > 0 && (
            <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4">
              <h4 className="flex items-center gap-2 font-medium text-gray-900 dark:text-white mb-2">
                <UserGroupIcon className="h-5 w-5 text-green-500" />
                Security Groups ({expectedGroups.length})
              </h4>
              <div className="grid grid-cols-3 gap-2 text-sm text-gray-600 dark:text-gray-400">
                {expectedGroups.map((group, i) => (
                  <div key={i} className="truncate" title={group}>
                    {group}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {error && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
          <div className="flex items-center gap-2 text-red-800 dark:text-red-200">
            <XCircleIcon className="h-5 w-5" />
            <span>{error}</span>
          </div>
        </div>
      )}

      <div className="flex justify-between">
        <button
          onClick={() => setStep("configure")}
          className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
        >
          Back
        </button>
        <button
          onClick={executeInitialization}
          disabled={loading}
          className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors disabled:opacity-50"
        >
          Create Objects
        </button>
      </div>
    </div>
  );

  const renderExecuteStep = () => (
    <div className="space-y-6">
      <div className="text-center">
        <ArrowPathIcon className="h-16 w-16 mx-auto text-blue-500 animate-spin" />
        <h2 className="mt-4 text-xl font-semibold text-gray-900 dark:text-white">
          Initializing...
        </h2>
        <p className="mt-2 text-gray-600 dark:text-gray-400">
          Creating AD objects. This may take a moment.
        </p>
      </div>
    </div>
  );

  const renderSkipWarning = () => (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-[60]">
      <div className="bg-white dark:bg-surface-800 rounded-xl shadow-2xl max-w-md w-full mx-4 p-6">
        <div className="text-center mb-4">
          <ExclamationTriangleIcon className="h-16 w-16 mx-auto text-amber-500" />
          <h2 className="mt-4 text-xl font-semibold text-gray-900 dark:text-white">
            Skip Initialization?
          </h2>
        </div>

        <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg p-4 mb-4">
          <p className="text-amber-800 dark:text-amber-200 text-sm font-medium mb-2">
            Warning: Skipping initialization will result in incomplete data.
          </p>
          <ul className="text-amber-700 dark:text-amber-300 text-sm list-disc list-inside space-y-1">
            <li>Tier assignments will not be accurate</li>
            <li>Objects will appear as "Unassigned"</li>
            <li>Compliance checks may show false violations</li>
            <li>GPO restrictions will not be enforced</li>
          </ul>
        </div>

        <p className="text-gray-600 dark:text-gray-400 text-sm mb-6">
          The AD Tier Model requires the OU structure and security groups to be created before it can properly categorize and manage your Active Directory objects.
        </p>

        <div className="flex justify-end gap-3">
          <button
            onClick={() => setShowSkipWarning(false)}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            Go Back
          </button>
          <button
            onClick={() => {
              setShowSkipWarning(false);
              onSkip();
            }}
            className="px-4 py-2 text-amber-700 dark:text-amber-400 bg-amber-100 dark:bg-amber-900/30 hover:bg-amber-200 dark:hover:bg-amber-900/50 rounded-lg transition-colors"
          >
            Skip Anyway
          </button>
        </div>
      </div>
    </div>
  );

  const renderCompleteStep = () => (
    <div className="space-y-6">
      <div className="text-center">
        {result?.success ? (
          <>
            <CheckCircleIcon className="h-16 w-16 mx-auto text-green-500" />
            <h2 className="mt-4 text-xl font-semibold text-gray-900 dark:text-white">
              Initialization Complete
            </h2>
            <p className="mt-2 text-gray-600 dark:text-gray-400">
              The AD Tier Model structure has been created.
            </p>
          </>
        ) : (
          <>
            <ExclamationTriangleIcon className="h-16 w-16 mx-auto text-amber-500" />
            <h2 className="mt-4 text-xl font-semibold text-gray-900 dark:text-white">
              Initialization Completed with Warnings
            </h2>
          </>
        )}
      </div>

      {result && (
        <div className="space-y-4 max-h-60 overflow-auto">
          {result.ousCreated.length > 0 && (
            <div className="bg-green-50 dark:bg-green-900/20 rounded-lg p-3">
              <div className="flex items-center gap-2 text-green-800 dark:text-green-200 font-medium">
                <CheckCircleIcon className="h-5 w-5" />
                {result.ousCreated.length} OUs created
              </div>
            </div>
          )}

          {result.groupsCreated.length > 0 && (
            <div className="bg-green-50 dark:bg-green-900/20 rounded-lg p-3">
              <div className="flex items-center gap-2 text-green-800 dark:text-green-200 font-medium">
                <CheckCircleIcon className="h-5 w-5" />
                {result.groupsCreated.length} groups created
              </div>
            </div>
          )}

          {result.permissionsSet && result.permissionsSet.length > 0 && (
            <div className="bg-green-50 dark:bg-green-900/20 rounded-lg p-3">
              <div className="flex items-center gap-2 text-green-800 dark:text-green-200 font-medium">
                <CheckCircleIcon className="h-5 w-5" />
                {result.permissionsSet.length} permissions configured
              </div>
            </div>
          )}

          {result.gposCreated && result.gposCreated.length > 0 && (
            <div className="bg-green-50 dark:bg-green-900/20 rounded-lg p-3">
              <div className="flex items-center gap-2 text-green-800 dark:text-green-200 font-medium">
                <CheckCircleIcon className="h-5 w-5" />
                {result.gposCreated.length} GPOs created
              </div>
            </div>
          )}

          {result.warnings.length > 0 && (
            <div className="bg-amber-50 dark:bg-amber-900/20 rounded-lg p-3">
              <div className="flex items-center gap-2 text-amber-800 dark:text-amber-200 font-medium mb-2">
                <ExclamationTriangleIcon className="h-5 w-5" />
                Warnings
              </div>
              <ul className="text-sm text-amber-700 dark:text-amber-300 list-disc list-inside">
                {result.warnings.map((warning, i) => (
                  <li key={i}>{warning}</li>
                ))}
              </ul>
            </div>
          )}

          {result.errors.length > 0 && (
            <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-3">
              <div className="flex items-center gap-2 text-red-800 dark:text-red-200 font-medium mb-2">
                <XCircleIcon className="h-5 w-5" />
                Errors
              </div>
              <ul className="text-sm text-red-700 dark:text-red-300 list-disc list-inside">
                {result.errors.map((error, i) => (
                  <li key={i}>{error}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      <div className="flex justify-center">
        <button
          onClick={onComplete}
          className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          Continue to Dashboard
        </button>
      </div>
    </div>
  );

  return (
    <>
      <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
        <div className="bg-white dark:bg-surface-800 rounded-xl shadow-2xl max-w-lg w-full mx-4 p-6">
          {step === "check" && renderCheckStep()}
          {step === "configure" && renderConfigureStep()}
          {step === "preview" && renderPreviewStep()}
          {step === "execute" && renderExecuteStep()}
          {step === "complete" && renderCompleteStep()}
        </div>
      </div>
      {showSkipWarning && renderSkipWarning()}
    </>
  );
}
