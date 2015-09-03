/*
 * Copyright 2014 Sander Verdonschot <sander.verdonschot at gmail.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package checker;

import java.io.FileDescriptor;
import java.io.FilePermission;
import java.net.InetAddress;
import java.nio.file.Path;
import java.security.AccessControlException;
import java.security.Permission;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

/**
 *
 * @author Sander Verdonschot <sander.verdonschot at gmail.com>
 */
public class StudentSecurityManager extends SecurityManager {

    private final Set<String> allowedActions = new HashSet<>(Arrays.asList(
            "control", "shutdownHooks", "javax.accessibility.assistive_technologies",
            "getenv.DISPLAY", "getProperty.networkaddress.cache.ttl",
            "getProperty.networkaddress.cache.negative.ttl", "accessDeclaredMembers",
            "specifyStreamHandler", "accessClassInPackage.sun.text.resources",
            "suppressAccessChecks", "accessClassInPackage.sun.util.resources",
            "accessClassInPackage.sun.reflect", "accessClassInPackage.sun.awt.resources",
            "stopThread", "accessClassInPackage.sun.text.resources.en",
            "accessClassInPackage.sun.util.resources.en", "getProtectionDomain",
            "user.timezone"
    ));
    private final Set<String> accessibleLibraries = new HashSet<>(Arrays.asList(
            "net", "nio", "awt", "fontmanager"
    ));
    private final int validExit = ((new Random()).nextInt(240) + 5);
    private final Checker checker;

    public StudentSecurityManager(Checker checker) {
        this.checker = checker;
    }

    /**
     * Terminates the JVM. Package access only.
     */
    void exit() {
        System.exit(validExit);
    }

    @Override
    public void checkExit(int code) {
        // Don't allow students to terminate the JVM
        if (code != validExit) {
            throw new ExitTrappedException();
        }
    }

    @Override
    public void checkPermission(Permission perm) {
        if (perm instanceof FilePermission) {
            FilePermission fp = (FilePermission) perm;

            if (fp.getActions().contains("read")) {
                checkRead(fp.getName());
            }
            if (fp.getActions().contains("write")) {
                checkWrite(fp.getName());
            }
            if (fp.getActions().contains("delete")) {
                checkDelete(fp.getName());
            }
            if (fp.getActions().contains("execute")) {
                checkExec(fp.getName());
            }
        } else if (!allowedActions.contains(perm.getName())) {
            SecurityException se = new SecurityException("checkPermission: perm=" + perm.toString() + " name=" + perm.getName());
            checker.securityBreach(se.getMessage());
            throw se;
        }
    }

    @Override
    public void checkDelete(String file) {
        // Don't allow deletion of any files
        AccessControlException se = new AccessControlException("Deletion of file \"" + file + "\" denied.");
        checker.securityBreach(se.getMessage());
        throw se;
    }

    @Override
    public void checkRead(String file) {
        // Allow Java to read all files that it needs to.
        if (file.startsWith(System.getProperty("java.home"))
                || file.endsWith(".class") || file.endsWith(".jar") || file.endsWith(".properties")) {
            // allow
            return;
        }

        // Allow reading from the readable directories
        for (Path dir : checker.getReadDirectories()) {
            if (file.startsWith(dir.toString())) {
                // allow
                return;
            }
        }

        // Don't allow access to any other part of the system
        AccessControlException se = new AccessControlException("Read access to file \"" + file + "\" denied.");
        checker.securityBreach(se.getMessage());
        throw se;
    }

    @Override
    public void checkWrite(String file) {
        // Allow writing to files in the writable directories
        for (Path dir : checker.getWriteDirectories()) {
            if (file.startsWith(dir.toString())) {
                // allow
                return;
            }
        }

        // Don't allow access to any other part of the system
        AccessControlException se = new AccessControlException("Write access to file \"" + file + "\" denied.");
        checker.securityBreach(se.getMessage());
        throw se;
    }

    @Override
    public void checkPropertyAccess(String key) {
        // There are too many of these that are required by various Java classes to function.
        // I also don't think allowing access to all of them is a large security risk.
    }

    @Override
    public void checkAccept(String host, int port) {
        SecurityException se = new SecurityException("checkAccept: host=" + host + " port=" + port);
        checker.securityBreach(se.getMessage());
        throw se;
    }

    @Override
    public void checkConnect(String host, int port) {
        SecurityException se = new SecurityException("checkConnect: host=" + host + " port=" + port);
        checker.securityBreach(se.getMessage());
        throw se;
    }

    @Override
    public void checkConnect(String host, int port, Object context) {
        SecurityException se = new SecurityException("checkConnect: host=" + host + " port=" + port + " context=" + context);
        checker.securityBreach(se.getMessage());
        throw se;
    }

    @Override
    public void checkCreateClassLoader() {
        // Allow the creation of a class loader
    }

    @Override
    public void checkExec(String cmd) {
        SecurityException se = new SecurityException("Execution of file or command \"" + cmd + "\" denied.");
        checker.securityBreach(se.getMessage());
        throw se;
    }

    @Override
    public void checkLink(String lib) {
        if (accessibleLibraries.contains(lib) || lib.startsWith(System.getProperty("java.home"))) {
            // allow
            return;
        }

        SecurityException se = new SecurityException("Access to library \"" + lib + "\" denied.");
        checker.securityBreach(se.getMessage());
        throw se;
    }

    @Override
    public void checkListen(int port) {
        SecurityException se = new SecurityException("checkListen: port=" + port);
        checker.securityBreach(se.getMessage());
        throw se;
    }

    @Override
    public void checkMulticast(InetAddress maddr) {
        SecurityException se = new SecurityException("checkMulticast: maddr=" + maddr);
        checker.securityBreach(se.getMessage());
        throw se;
    }

    @Override
    public void checkPermission(Permission perm, Object context) {
        SecurityException se = new SecurityException("checkPermission: perm=" + perm + " context=" + context);
        checker.securityBreach(se.getMessage());
        throw se;
    }

    @Override
    public void checkPrintJobAccess() {
        SecurityException se = new SecurityException("checkPrintJobAccess");
        checker.securityBreach(se.getMessage());
        throw se;
    }

    @Override
    public void checkPropertiesAccess() {
        SecurityException se = new SecurityException("checkPropertiesAccess");
        checker.securityBreach(se.getMessage());
        throw se;
    }

    @Override
    public void checkRead(FileDescriptor fd) {
        SecurityException se = new SecurityException("checkRead: fd=" + fd);
        checker.securityBreach(se.getMessage());
        throw se;
    }

    @Override
    public void checkRead(String file, Object context) {
        SecurityException se = new SecurityException("checkRead: file=" + file + " context=" + context);
        checker.securityBreach(se.getMessage());
        throw se;
    }

    @Override
    public void checkSecurityAccess(String target) {
        SecurityException se = new SecurityException("checkSecurityAccess: target=" + target);
        checker.securityBreach(se.getMessage());
        throw se;
    }

    @Override
    public void checkSetFactory() {
        SecurityException se = new SecurityException("checkSetFactory");
        checker.securityBreach(se.getMessage());
        throw se;
    }

    @Override
    public void checkWrite(FileDescriptor fd) {
        SecurityException se = new SecurityException("checkWrite: fd=" + fd);
        checker.securityBreach(se.getMessage());
        throw se;
    }

    static class ExitTrappedException extends SecurityException {
    }
}
