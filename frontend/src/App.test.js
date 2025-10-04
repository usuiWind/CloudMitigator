import { render, screen } from '@testing-library/react';
import App from './App';

test('renders CloudMitigator header', () => {
  render(<App />);
  const headerElement = screen.getByText(/CloudMitigator/i);
  expect(headerElement).toBeInTheDocument();
});

test('renders search bar', () => {
  render(<App />);
  const searchInput = screen.getByPlaceholderText(/search/i);
  expect(searchInput).toBeInTheDocument();
});
