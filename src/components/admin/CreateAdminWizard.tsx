import { useState, useMemo } from "react";
import { Dialog } from "@headlessui/react";
import {
  XMarkIcon,
  UserPlusIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  ShieldCheckIcon,
  CogIcon,
  EyeIcon,
  EyeSlashIcon,
  ClipboardDocumentIcon,
} from "@heroicons/react/24/outline";
import { useQueryClient } from "@tanstack/react-query";
import { createAdminAccount, type GroupSuffix } from "../../services/tauri";
import { tierConfig, type TierLevel } from "../../types/tier";
import { logAudit } from "../../store/auditStore";

interface CreateAdminWizardProps {
  isOpen: boolean;
  onClose: () => void;
  defaultTier?: TierLevel;
}

type WizardStep = "basics" | "security" | "groups" | "review";

interface FormData {
  baseUsername: string;
  displayName: string;
  targetTier: TierLevel;
  accountType: "admin" | "service";
  description: string;
  password: string;
  confirmPassword: string;
  groups: GroupSuffix[];
  enabled: boolean;
}

const groupOptions: { value: GroupSuffix; label: string; description: string }[] = [
  { value: "Admins", label: "Admins", description: "Full administrative access to tier resources" },
  { value: "Operators", label: "Operators", description: "Operational access for day-to-day tasks" },
  { value: "Readers", label: "Readers", description: "Read-only access to tier resources" },
  { value: "ServiceAccounts", label: "Service Accounts", description: "Service account group membership" },
  { value: "JumpServers", label: "Jump Servers", description: "Access to tier jump servers" },
];

export function CreateAdminWizard({ isOpen, onClose, defaultTier = "Tier1" }: CreateAdminWizardProps) {
  const queryClient = useQueryClient();

  const [currentStep, setCurrentStep] = useState<WizardStep>("basics");
  const [isCreating, setIsCreating] = useState(false);
  const [result, setResult] = useState<{ success: boolean; samAccountName?: string; error?: string } | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [copiedPassword, setCopiedPassword] = useState(false);

  const [formData, setFormData] = useState<FormData>({
    baseUsername: "",
    displayName: "",
    targetTier: defaultTier,
    accountType: "admin",
    description: "",
    password: "",
    confirmPassword: "",
    groups: ["Admins"],
    enabled: true,
  });

  // Generate the actual SAM account name preview
  const samAccountPreview = useMemo(() => {
    const tierNum = formData.targetTier.replace("Tier", "");
    const prefix = formData.accountType === "admin" ? "adm" : "svc";
    return formData.baseUsername ? `${prefix}-t${tierNum}-${formData.baseUsername}` : "";
  }, [formData.baseUsername, formData.targetTier, formData.accountType]);

  // Validation
  const validation = useMemo(() => {
    const errors: string[] = [];

    if (!formData.baseUsername) {
      errors.push("Username is required");
    } else if (!/^[a-zA-Z0-9_-]+$/.test(formData.baseUsername)) {
      errors.push("Username can only contain letters, numbers, underscores, and hyphens");
    } else if (formData.baseUsername.length < 2) {
      errors.push("Username must be at least 2 characters");
    }

    if (!formData.displayName) {
      errors.push("Display name is required");
    }

    if (!formData.password) {
      errors.push("Password is required");
    } else if (formData.password.length < 8) {
      errors.push("Password must be at least 8 characters");
    }

    if (formData.password !== formData.confirmPassword) {
      errors.push("Passwords do not match");
    }

    if (formData.groups.length === 0) {
      errors.push("Select at least one group");
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }, [formData]);

  const steps: { id: WizardStep; label: string }[] = [
    { id: "basics", label: "Account Details" },
    { id: "security", label: "Security" },
    { id: "groups", label: "Group Membership" },
    { id: "review", label: "Review & Create" },
  ];

  const currentStepIndex = steps.findIndex((s) => s.id === currentStep);

  const handleNext = () => {
    const nextIndex = currentStepIndex + 1;
    if (nextIndex < steps.length) {
      setCurrentStep(steps[nextIndex].id);
    }
  };

  const handleBack = () => {
    const prevIndex = currentStepIndex - 1;
    if (prevIndex >= 0) {
      setCurrentStep(steps[prevIndex].id);
    }
  };

  const generatePassword = () => {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*";
    let password = "";
    for (let i = 0; i < 16; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    setFormData((prev) => ({ ...prev, password, confirmPassword: password }));
  };

  const copyPassword = async () => {
    await navigator.clipboard.writeText(formData.password);
    setCopiedPassword(true);
    setTimeout(() => setCopiedPassword(false), 2000);
  };

  const handleCreate = async () => {
    if (!validation.isValid) return;

    setIsCreating(true);
    try {
      const response = await createAdminAccount({
        baseUsername: formData.baseUsername,
        displayName: formData.displayName,
        targetTier: formData.targetTier,
        accountType: formData.accountType,
        description: formData.description || undefined,
        password: formData.password,
        groups: formData.groups,
        enabled: formData.enabled,
      });

      if (response.success) {
        setResult({ success: true, samAccountName: response.samAccountName });

        logAudit(
          "create_account",
          `Created ${formData.accountType} account ${response.samAccountName} in ${formData.targetTier}`,
          [response.accountDn || response.samAccountName],
          true,
          {
            targetTier: formData.targetTier,
            details: {
              accountType: formData.accountType,
              groupsAdded: response.groupsAdded,
            },
          }
        );

        // Refresh tier data
        queryClient.invalidateQueries({ queryKey: ["tierMembers"] });
        queryClient.invalidateQueries({ queryKey: ["tierCounts"] });
      } else {
        setResult({ success: false, error: response.error || "Unknown error" });
      }
    } catch (error) {
      setResult({ success: false, error: String(error) });
    } finally {
      setIsCreating(false);
    }
  };

  const handleClose = () => {
    setCurrentStep("basics");
    setFormData({
      baseUsername: "",
      displayName: "",
      targetTier: defaultTier,
      accountType: "admin",
      description: "",
      password: "",
      confirmPassword: "",
      groups: ["Admins"],
      enabled: true,
    });
    setResult(null);
    onClose();
  };

  const config = tierConfig[formData.targetTier];

  return (
    <Dialog open={isOpen} onClose={handleClose} className="relative z-50">
      <div className="fixed inset-0 bg-black/50" aria-hidden="true" />

      <div className="fixed inset-0 flex items-center justify-center p-4">
        <Dialog.Panel className="w-full max-w-2xl bg-white dark:bg-surface-850 rounded-xl shadow-2xl">
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${config.bgColor}`}>
                <UserPlusIcon className={`w-5 h-5 ${config.textColor}`} />
              </div>
              <Dialog.Title className="text-lg font-semibold text-gray-900 dark:text-white">
                Create {formData.targetTier} Admin Account
              </Dialog.Title>
            </div>
            <button onClick={handleClose} className="p-2 hover:bg-gray-100 dark:hover:bg-surface-700 rounded-lg">
              <XMarkIcon className="w-5 h-5 text-gray-500" />
            </button>
          </div>

          {/* Progress Steps */}
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              {steps.map((step, index) => (
                <div key={step.id} className="flex items-center">
                  <div
                    className={`flex items-center justify-center w-8 h-8 rounded-full text-sm font-medium ${
                      index < currentStepIndex
                        ? "bg-green-500 text-white"
                        : index === currentStepIndex
                        ? `${config.bgColor} ${config.textColor}`
                        : "bg-gray-200 dark:bg-surface-700 text-gray-500 dark:text-gray-400"
                    }`}
                  >
                    {index < currentStepIndex ? <CheckCircleIcon className="w-5 h-5" /> : index + 1}
                  </div>
                  <span
                    className={`ml-2 text-sm ${
                      index === currentStepIndex
                        ? "font-medium text-gray-900 dark:text-white"
                        : "text-gray-500 dark:text-gray-400"
                    }`}
                  >
                    {step.label}
                  </span>
                  {index < steps.length - 1 && (
                    <div className="w-12 h-px bg-gray-300 dark:bg-gray-600 mx-4" />
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Content */}
          <div className="p-6 min-h-[320px]">
            {result ? (
              // Result Screen
              <div className="flex flex-col items-center justify-center h-full py-8">
                {result.success ? (
                  <>
                    <div className="w-16 h-16 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center mb-4">
                      <CheckCircleIcon className="w-10 h-10 text-green-600 dark:text-green-400" />
                    </div>
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                      Account Created Successfully
                    </h3>
                    <p className="text-gray-600 dark:text-gray-400 mb-4">
                      SAM Account Name: <span className="font-mono font-medium">{result.samAccountName}</span>
                    </p>
                    <button
                      onClick={handleClose}
                      className={`px-6 py-2 rounded-lg text-white font-medium ${config.bgColor.replace('bg-', 'bg-').replace('/20', '')} hover:opacity-90`}
                    >
                      Done
                    </button>
                  </>
                ) : (
                  <>
                    <div className="w-16 h-16 rounded-full bg-red-100 dark:bg-red-900/30 flex items-center justify-center mb-4">
                      <ExclamationTriangleIcon className="w-10 h-10 text-red-600 dark:text-red-400" />
                    </div>
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                      Account Creation Failed
                    </h3>
                    <p className="text-red-600 dark:text-red-400 text-center mb-4">{result.error}</p>
                    <button
                      onClick={() => setResult(null)}
                      className="px-6 py-2 rounded-lg bg-gray-100 dark:bg-surface-700 text-gray-700 dark:text-gray-300 font-medium hover:bg-gray-200 dark:hover:bg-surface-600"
                    >
                      Try Again
                    </button>
                  </>
                )}
              </div>
            ) : (
              <>
                {/* Step 1: Basics */}
                {currentStep === "basics" && (
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                          Target Tier
                        </label>
                        <select
                          value={formData.targetTier}
                          onChange={(e) => setFormData((prev) => ({ ...prev, targetTier: e.target.value as TierLevel }))}
                          className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-surface-900 text-gray-900 dark:text-white"
                        >
                          <option value="Tier0">Tier 0 - Infrastructure</option>
                          <option value="Tier1">Tier 1 - Servers</option>
                          <option value="Tier2">Tier 2 - Workstations</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                          Account Type
                        </label>
                        <select
                          value={formData.accountType}
                          onChange={(e) => setFormData((prev) => ({ ...prev, accountType: e.target.value as "admin" | "service" }))}
                          className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-surface-900 text-gray-900 dark:text-white"
                        >
                          <option value="admin">Admin Account</option>
                          <option value="service">Service Account</option>
                        </select>
                      </div>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Base Username
                      </label>
                      <input
                        type="text"
                        value={formData.baseUsername}
                        onChange={(e) => setFormData((prev) => ({ ...prev, baseUsername: e.target.value.toLowerCase() }))}
                        placeholder="e.g., jsmith"
                        className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-surface-900 text-gray-900 dark:text-white"
                      />
                      {samAccountPreview && (
                        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                          SAM Account Name: <span className="font-mono font-medium">{samAccountPreview}</span>
                        </p>
                      )}
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Display Name
                      </label>
                      <input
                        type="text"
                        value={formData.displayName}
                        onChange={(e) => setFormData((prev) => ({ ...prev, displayName: e.target.value }))}
                        placeholder="e.g., John Smith (Tier1 Admin)"
                        className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-surface-900 text-gray-900 dark:text-white"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Description (Optional)
                      </label>
                      <input
                        type="text"
                        value={formData.description}
                        onChange={(e) => setFormData((prev) => ({ ...prev, description: e.target.value }))}
                        placeholder="e.g., Server administrator for finance department"
                        className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-surface-900 text-gray-900 dark:text-white"
                      />
                    </div>
                  </div>
                )}

                {/* Step 2: Security */}
                {currentStep === "security" && (
                  <div className="space-y-4">
                    <div className="p-4 bg-amber-50 dark:bg-amber-900/20 rounded-lg border border-amber-200 dark:border-amber-800">
                      <div className="flex items-start gap-3">
                        <ShieldCheckIcon className="w-5 h-5 text-amber-600 dark:text-amber-400 mt-0.5" />
                        <div>
                          <h4 className="text-sm font-medium text-amber-800 dark:text-amber-200">Password Requirements</h4>
                          <p className="text-sm text-amber-700 dark:text-amber-300 mt-1">
                            Use a strong password with at least 8 characters. Consider using the generator for maximum security.
                          </p>
                        </div>
                      </div>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Password
                      </label>
                      <div className="flex gap-2">
                        <div className="relative flex-1">
                          <input
                            type={showPassword ? "text" : "password"}
                            value={formData.password}
                            onChange={(e) => setFormData((prev) => ({ ...prev, password: e.target.value }))}
                            className="w-full px-3 py-2 pr-20 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-surface-900 text-gray-900 dark:text-white font-mono"
                          />
                          <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
                            <button
                              type="button"
                              onClick={() => setShowPassword(!showPassword)}
                              className="p-1 hover:bg-gray-100 dark:hover:bg-surface-700 rounded"
                            >
                              {showPassword ? (
                                <EyeSlashIcon className="w-4 h-4 text-gray-500" />
                              ) : (
                                <EyeIcon className="w-4 h-4 text-gray-500" />
                              )}
                            </button>
                            <button
                              type="button"
                              onClick={copyPassword}
                              className="p-1 hover:bg-gray-100 dark:hover:bg-surface-700 rounded"
                              disabled={!formData.password}
                            >
                              <ClipboardDocumentIcon className={`w-4 h-4 ${copiedPassword ? "text-green-500" : "text-gray-500"}`} />
                            </button>
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={generatePassword}
                          className="px-4 py-2 bg-gray-100 dark:bg-surface-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-surface-600 text-sm font-medium"
                        >
                          Generate
                        </button>
                      </div>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Confirm Password
                      </label>
                      <input
                        type={showPassword ? "text" : "password"}
                        value={formData.confirmPassword}
                        onChange={(e) => setFormData((prev) => ({ ...prev, confirmPassword: e.target.value }))}
                        className={`w-full px-3 py-2 rounded-lg border bg-white dark:bg-surface-900 text-gray-900 dark:text-white font-mono ${
                          formData.confirmPassword && formData.password !== formData.confirmPassword
                            ? "border-red-500"
                            : "border-gray-300 dark:border-gray-600"
                        }`}
                      />
                      {formData.confirmPassword && formData.password !== formData.confirmPassword && (
                        <p className="mt-1 text-sm text-red-500">Passwords do not match</p>
                      )}
                    </div>

                    <div className="flex items-center gap-3 pt-2">
                      <input
                        type="checkbox"
                        id="enabled"
                        checked={formData.enabled}
                        onChange={(e) => setFormData((prev) => ({ ...prev, enabled: e.target.checked }))}
                        className="w-4 h-4 rounded border-gray-300 dark:border-gray-600"
                      />
                      <label htmlFor="enabled" className="text-sm text-gray-700 dark:text-gray-300">
                        Enable account immediately after creation
                      </label>
                    </div>
                  </div>
                )}

                {/* Step 3: Groups */}
                {currentStep === "groups" && (
                  <div className="space-y-4">
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      Select the tier groups to add this account to:
                    </p>

                    <div className="space-y-3">
                      {groupOptions.map((group) => (
                        <label
                          key={group.value}
                          className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                            formData.groups.includes(group.value)
                              ? `${config.bgColor} ${config.borderColor} border-2`
                              : "border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-surface-800"
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={formData.groups.includes(group.value)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setFormData((prev) => ({ ...prev, groups: [...prev.groups, group.value] }));
                              } else {
                                setFormData((prev) => ({ ...prev, groups: prev.groups.filter((g) => g !== group.value) }));
                              }
                            }}
                            className="mt-0.5 w-4 h-4 rounded border-gray-300 dark:border-gray-600"
                          />
                          <div>
                            <div className="font-medium text-gray-900 dark:text-white">
                              {formData.targetTier}-{group.label}
                            </div>
                            <div className="text-sm text-gray-500 dark:text-gray-400">{group.description}</div>
                          </div>
                        </label>
                      ))}
                    </div>
                  </div>
                )}

                {/* Step 4: Review */}
                {currentStep === "review" && (
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="p-4 bg-gray-50 dark:bg-surface-900 rounded-lg">
                        <div className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-1">Account Name</div>
                        <div className="font-mono font-medium text-gray-900 dark:text-white">{samAccountPreview}</div>
                      </div>
                      <div className="p-4 bg-gray-50 dark:bg-surface-900 rounded-lg">
                        <div className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-1">Target Tier</div>
                        <div className={`font-medium ${config.textColor}`}>{config.label}</div>
                      </div>
                      <div className="p-4 bg-gray-50 dark:bg-surface-900 rounded-lg">
                        <div className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-1">Display Name</div>
                        <div className="text-gray-900 dark:text-white">{formData.displayName}</div>
                      </div>
                      <div className="p-4 bg-gray-50 dark:bg-surface-900 rounded-lg">
                        <div className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-1">Account Type</div>
                        <div className="text-gray-900 dark:text-white capitalize">{formData.accountType} Account</div>
                      </div>
                    </div>

                    <div className="p-4 bg-gray-50 dark:bg-surface-900 rounded-lg">
                      <div className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-2">Group Memberships</div>
                      <div className="flex flex-wrap gap-2">
                        {formData.groups.map((group) => (
                          <span
                            key={group}
                            className={`px-2 py-1 rounded text-sm ${config.bgColor} ${config.textColor}`}
                          >
                            {formData.targetTier}-{group}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="flex items-center gap-2 p-4 bg-gray-50 dark:bg-surface-900 rounded-lg">
                      <CogIcon className="w-5 h-5 text-gray-500" />
                      <span className="text-sm text-gray-700 dark:text-gray-300">
                        Account will be {formData.enabled ? "enabled" : "disabled"} after creation
                      </span>
                    </div>

                    {!validation.isValid && (
                      <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800">
                        <div className="flex items-start gap-3">
                          <ExclamationTriangleIcon className="w-5 h-5 text-red-600 dark:text-red-400 mt-0.5" />
                          <div>
                            <h4 className="text-sm font-medium text-red-800 dark:text-red-200">Please fix the following:</h4>
                            <ul className="text-sm text-red-700 dark:text-red-300 mt-1 list-disc list-inside">
                              {validation.errors.map((error, i) => (
                                <li key={i}>{error}</li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </>
            )}
          </div>

          {/* Footer */}
          {!result && (
            <div className="flex items-center justify-between px-6 py-4 border-t border-gray-200 dark:border-gray-700">
              <button
                onClick={handleBack}
                disabled={currentStepIndex === 0}
                className="flex items-center gap-1 px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-surface-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronLeftIcon className="w-4 h-4" />
                Back
              </button>

              {currentStep === "review" ? (
                <button
                  onClick={handleCreate}
                  disabled={!validation.isValid || isCreating}
                  className={`flex items-center gap-2 px-6 py-2 rounded-lg text-white font-medium disabled:opacity-50 disabled:cursor-not-allowed ${
                    formData.targetTier === "Tier0"
                      ? "bg-red-600 hover:bg-red-700"
                      : formData.targetTier === "Tier1"
                      ? "bg-amber-600 hover:bg-amber-700"
                      : "bg-green-600 hover:bg-green-700"
                  }`}
                >
                  {isCreating ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      Creating...
                    </>
                  ) : (
                    <>
                      <UserPlusIcon className="w-4 h-4" />
                      Create Account
                    </>
                  )}
                </button>
              ) : (
                <button
                  onClick={handleNext}
                  className={`flex items-center gap-1 px-4 py-2 rounded-lg text-white font-medium ${
                    formData.targetTier === "Tier0"
                      ? "bg-red-600 hover:bg-red-700"
                      : formData.targetTier === "Tier1"
                      ? "bg-amber-600 hover:bg-amber-700"
                      : "bg-green-600 hover:bg-green-700"
                  }`}
                >
                  Next
                  <ChevronRightIcon className="w-4 h-4" />
                </button>
              )}
            </div>
          )}
        </Dialog.Panel>
      </div>
    </Dialog>
  );
}
