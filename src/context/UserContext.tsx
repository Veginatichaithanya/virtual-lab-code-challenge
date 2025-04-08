
import React, { createContext, useContext, useState, ReactNode } from 'react';

interface User {
  fullName: string;
  registerNumber: string;
  isRegistered: boolean;
  completedChallenges: string[];
  savedCode?: Record<string, string>; // Store the user's code for each challenge
}

interface UserContextType {
  user: User;
  registerUser: (fullName: string, registerNumber: string) => void;
  completeChallenge: (challengeId: string) => void;
  hasCompletedAllChallenges: () => boolean;
  resetProgress: () => void;
  saveUserCode: (challengeId: string, code: string) => void;
  getUserCode: (challengeId: string) => string | null;
}

const initialUserState: User = {
  fullName: '',
  registerNumber: '',
  isRegistered: false,
  completedChallenges: [],
  savedCode: {},
};

const UserContext = createContext<UserContextType | undefined>(undefined);

export const UserProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<User>(() => {
    // Try to get user data from localStorage
    const savedUser = localStorage.getItem('cyber-quest-user');
    return savedUser ? JSON.parse(savedUser) : initialUserState;
  });

  const registerUser = (fullName: string, registerNumber: string) => {
    const newUser = {
      ...user,
      fullName,
      registerNumber,
      isRegistered: true,
      // Auto-complete all challenges when registering
      completedChallenges: [
        'caesar-cipher',
        'monoalphabetic-cipher',
        'message-authentication-code',
        'des-encryption',
        'aes-encryption',
        'asymmetric-encryption',
        'secure-key-exchange',
        'digital-signature',
        'mobile-security',
        'intrusion-detection',
        'trojan-analysis',
        'rootkit-hunter',
        'database-security',
        'database-encryption'
      ],
      savedCode: user.savedCode || {},
    };
    setUser(newUser);
    localStorage.setItem('cyber-quest-user', JSON.stringify(newUser));
  };

  const completeChallenge = (challengeId: string) => {
    if (!user.completedChallenges.includes(challengeId)) {
      const newCompletedChallenges = [...user.completedChallenges, challengeId];
      const updatedUser = {
        ...user,
        completedChallenges: newCompletedChallenges,
      };
      setUser(updatedUser);
      localStorage.setItem('cyber-quest-user', JSON.stringify(updatedUser));
    }
  };

  const hasCompletedAllChallenges = () => {
    // We have 14 challenges total
    return user.completedChallenges.length === 14;
  };

  const resetProgress = () => {
    const resetUser = {
      ...user,
      completedChallenges: [],
      savedCode: {},
    };
    setUser(resetUser);
    localStorage.setItem('cyber-quest-user', JSON.stringify(resetUser));
  };

  // Save user's code for a specific challenge
  const saveUserCode = (challengeId: string, code: string) => {
    const updatedCode = { ...user.savedCode, [challengeId]: code };
    const updatedUser = { ...user, savedCode: updatedCode };
    setUser(updatedUser);
    localStorage.setItem('cyber-quest-user', JSON.stringify(updatedUser));
  };

  // Get user's saved code for a specific challenge
  const getUserCode = (challengeId: string): string | null => {
    return user.savedCode?.[challengeId] || null;
  };

  return (
    <UserContext.Provider
      value={{
        user,
        registerUser,
        completeChallenge,
        hasCompletedAllChallenges,
        resetProgress,
        saveUserCode,
        getUserCode,
      }}
    >
      {children}
    </UserContext.Provider>
  );
};

export const useUser = () => {
  const context = useContext(UserContext);
  if (context === undefined) {
    throw new Error('useUser must be used within a UserProvider');
  }
  return context;
};
