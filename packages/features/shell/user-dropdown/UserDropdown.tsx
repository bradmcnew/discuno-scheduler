import { signOut, useSession } from "next-auth/react";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

import { ROADMAP, DESKTOP_APP_LINK } from "@calcom/lib/constants";
import { useLocale } from "@calcom/lib/hooks/useLocale";
import { useSimpleMode } from "@calcom/lib/simple-mode";
import useMeQuery from "@calcom/trpc/react/hooks/useMeQuery";
import classNames from "@calcom/ui/classNames";
import { Avatar } from "@calcom/ui/components/avatar";
import {
  Dropdown,
  DropdownItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuPortal,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@calcom/ui/components/dropdown";
import { Icon } from "@calcom/ui/components/icon";
// TODO (Platform): we shouldnt be importing from web here
import { useGetUserAttributes } from "@calcom/web/components/settings/platform/hooks/useGetUserAttributes";

import FreshChatProvider from "../../ee/support/lib/freshchat/FreshChatProvider";

declare global {
  interface Window {
    Plain?: {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      init: (config: any) => void;
      open: () => void;
    };
  }
}

interface UserDropdownProps {
  small?: boolean;
}

export function UserDropdown({ small }: UserDropdownProps) {
  const { isPlatformUser } = useGetUserAttributes();
  const { t } = useLocale();
  const { data: user, isPending } = useMeQuery();
  const pathname = usePathname();
  const isPlatformPages = pathname?.startsWith("/settings/platform");

  // [DISCUNO CUSTOMIZATION] Check if simple mode is enabled
  const { data: session } = useSession();
  const isSimpleMode = useSimpleMode(session);
  // [DISCUNO CUSTOMIZATION] End

  useEffect(() => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    //@ts-ignore
    const Beacon = window.Beacon;
    // window.Beacon is defined when user actually opens up HelpScout and username is available here. On every re-render update session info, so that it is always latest.
    Beacon &&
      Beacon("session-data", {
        username: user?.username || "Unknown",
        screenResolution: `${screen.width}x${screen.height}`,
      });
  });

  const [menuOpen, setMenuOpen] = useState(false);

  const handleHelpClick = () => {
    if (window.Plain) {
      window.Plain.open();
    }
    setMenuOpen(false);
  };

  // Prevent rendering dropdown if user isn't available.
  // We don't want to show nameless user.
  if (!user && !isPending) {
    return null;
  }

  return (
    <Dropdown open={menuOpen}>
      <DropdownMenuTrigger asChild onClick={() => setMenuOpen((menuOpen) => !menuOpen)} disabled={isPending}>
        <button
          data-testid="user-dropdown-trigger-button"
          className={classNames(
            "hover:bg-emphasis todesktop:!bg-transparent group mx-0 flex w-full cursor-pointer appearance-none items-center rounded-full text-left outline-none transition focus:outline-none focus:ring-0 md:rounded-none lg:rounded",
            small ? "p-2" : "px-2 py-1.5"
          )}>
          <span
            className={classNames(
              small ? "h-4 w-4" : "h-5 w-5 ltr:mr-2 rtl:ml-2",
              "relative flex-shrink-0 rounded-full"
            )}>
            <Avatar
              size={small ? "xs" : "xsm"}
              imageSrc={user?.avatarUrl ?? user?.avatar}
              alt={user?.username ? `${user.username} Avatar` : "Nameless User Avatar"}
              className="overflow-hidden"
            />
            <span
              className={classNames(
                "border-muted absolute -bottom-1 -right-1 rounded-full border bg-green-500",
                small ? "-bottom-0.5 -right-0.5 h-2.5 w-2.5" : "-bottom-0.5 -right-0 h-2 w-2"
              )}
            />
          </span>
          {!small && (
            <span className="flex flex-grow items-center gap-2">
              <span className="w-24 flex-shrink-0 text-sm leading-none">
                <span className="text-emphasis block truncate py-0.5 font-medium leading-normal">
                  {isPending ? "Loading..." : user?.name ?? "Nameless User"}
                </span>
              </span>
              <Icon
                name="chevron-down"
                className="group-hover:text-subtle text-muted h-4 w-4 flex-shrink-0 transition rtl:mr-4"
                aria-hidden="true"
              />
            </span>
          )}
        </button>
      </DropdownMenuTrigger>

      <DropdownMenuPortal>
        <FreshChatProvider>
          <DropdownMenuContent
            align="start"
            onInteractOutside={() => {
              setMenuOpen(false);
            }}
            className="group overflow-hidden rounded-md">
            <>
              {!isPlatformPages && (
                <>
                  <DropdownMenuItem>
                    <DropdownItem
                      type="button"
                      CustomStartIcon={
                        <Icon name="user" className="text-default h-4 w-4" aria-hidden="true" />
                      }
                      href="/settings/my-account/profile">
                      {t("my_profile")}
                    </DropdownItem>
                  </DropdownMenuItem>
                  <DropdownMenuItem>
                    <DropdownItem
                      type="button"
                      CustomStartIcon={
                        <Icon name="settings" className="text-default h-4 w-4" aria-hidden="true" />
                      }
                      href="/settings/my-account/general">
                      {t("my_settings")}
                    </DropdownItem>
                  </DropdownMenuItem>
                  {/* [DISCUNO CUSTOMIZATION] Conditionally include out of office based on simple mode */}
                  {!isSimpleMode && (
                    <DropdownMenuItem>
                      <DropdownItem
                        type="button"
                        CustomStartIcon={
                          <Icon name="moon" className="text-default h-4 w-4" aria-hidden="true" />
                        }
                        href="/settings/my-account/out-of-office">
                        {t("out_of_office")}
                      </DropdownItem>
                    </DropdownMenuItem>
                  )}
                  {/* [DISCUNO CUSTOMIZATION] End */}
                  <DropdownMenuSeparator />
                </>
              )}

              {/* [DISCUNO CUSTOMIZATION] Conditionally include roadmap based on simple mode */}
              {!isSimpleMode && (
                <DropdownMenuItem>
                  <DropdownItem StartIcon="map" target="_blank" href={ROADMAP}>
                    {t("visit_roadmap")}
                  </DropdownItem>
                </DropdownMenuItem>
              )}
              {/* [DISCUNO CUSTOMIZATION] End */}
              <DropdownMenuItem>
                <DropdownItem
                  type="button"
                  StartIcon="circle-help"
                  aria-hidden="true"
                  onClick={handleHelpClick}>
                  {t("help")}
                </DropdownItem>
              </DropdownMenuItem>
              {/* [DISCUNO CUSTOMIZATION] Conditionally include download desktop app based on simple mode */}
              {!isSimpleMode && !isPlatformPages && (
                <DropdownMenuItem className="todesktop:hidden hidden lg:flex">
                  <DropdownItem StartIcon="download" target="_blank" rel="noreferrer" href={DESKTOP_APP_LINK}>
                    {t("download_desktop_app")}
                  </DropdownItem>
                </DropdownMenuItem>
              )}
              {/* [DISCUNO CUSTOMIZATION] End */}
              {!isPlatformPages && isPlatformUser && (
                <DropdownMenuItem className="todesktop:hidden hidden lg:flex">
                  <DropdownItem StartIcon="blocks" target="_blank" rel="noreferrer" href="/settings/platform">
                    Platform
                  </DropdownItem>
                </DropdownMenuItem>
              )}
              <DropdownMenuSeparator />

              <DropdownMenuItem>
                <DropdownItem
                  type="button"
                  StartIcon="log-out"
                  aria-hidden="true"
                  onClick={() => {
                    signOut({ callbackUrl: "/auth/logout" });
                  }}>
                  {t("sign_out")}
                </DropdownItem>
              </DropdownMenuItem>
            </>
          </DropdownMenuContent>
        </FreshChatProvider>
      </DropdownMenuPortal>
    </Dropdown>
  );
}
